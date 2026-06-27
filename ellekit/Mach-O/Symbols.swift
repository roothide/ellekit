
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger


import Foundation

#if SWIFT_PACKAGE
import ellekitc
#endif

enum SymbolErr: Error {
    case noSymbol
    case noAddress
    case badCachePath
}

/// Mirrors dyld's `MachOAnalyzer::inCodeSection`: decides whether a resolved
/// symbol pointer should be PAC-signed the same way `dlsym` would.
///
/// dlsym only signs the returned pointer when **both** runtime conditions hold
/// (the compile-time `ptrauth_calls` condition is already handled inside
/// `sign_pointer`):
///   - the target image is arm64e (cputype/subtype check), and
///   - the symbol's address lands in a section flagged with instruction
///     attributes (i.e. it points to code, not data).
///
/// `vmaddr` must be the symbol's *unslid* link-time address (`nlist_64.n_value`),
/// which shares the same address space as each `section_64.addr` in the
/// in-memory load commands, so no slide adjustment is needed here.
func symbolTargetIsCode(image machHeaderPointer: UnsafeRawPointer, vmaddr: UInt64) -> Bool {

    let machHeader = machHeaderPointer.assumingMemoryBound(to: mach_header_64.self).pointee

    // Condition: image must be arm64e (capability bits masked off).
    let subtype = UInt32(bitPattern: machHeader.cpusubtype) & ~UInt32(CPU_SUBTYPE_MASK)
    guard machHeader.cputype == CPU_TYPE_ARM64, subtype == UInt32(CPU_SUBTYPE_ARM64E) else {
        return false
    }

    let codeAttrs = UInt32(S_ATTR_PURE_INSTRUCTIONS) | UInt32(S_ATTR_SOME_INSTRUCTIONS)

    var command = machHeaderPointer.advanced(by: MemoryLayout<mach_header_64>.size)
    for _ in 0..<machHeader.ncmds {
        let load_command = command.assumingMemoryBound(to: load_command.self).pointee
        if load_command.cmd == LC_SEGMENT_64 {
            let segment = command.assumingMemoryBound(to: segment_command_64.self).pointee
            var sectionPtr = command.advanced(by: MemoryLayout<segment_command_64>.size)
            for _ in 0..<segment.nsects {
                let section = sectionPtr.assumingMemoryBound(to: section_64.self).pointee
                if vmaddr >= section.addr, vmaddr < section.addr &+ section.size {
                    return (section.flags & codeAttrs) != 0
                }
                sectionPtr = sectionPtr.advanced(by: MemoryLayout<section_64>.size)
            }
        }
        command = command.advanced(by: Int(load_command.cmdsize))
    }
    return false
}

// Thanks to opa334 for the help
public func findSymbol(
    image machHeaderPointer: UnsafeRawPointer,
    symbol symbolName: String
) throws -> UnsafeRawPointer? {
    
    let machHeader = machHeaderPointer.assumingMemoryBound(to: mach_header_64.self).pointee
        
    // Read the load commands
    var command = machHeaderPointer.advanced(by: MemoryLayout<mach_header_64>.size)
    var commandIt = command;

    // First iteration: Get symtab pointer
    var symtab_cmd: symtab_command?
    
    for _ in 0..<machHeader.ncmds {
        let load_command = commandIt.assumingMemoryBound(to: load_command.self).pointee
        if load_command.cmd == LC_SYMTAB {
            symtab_cmd = commandIt.assumingMemoryBound(to: symtab_command.self).pointee
            break;
        }
        commandIt = commandIt.advanced(by: Int(load_command.cmdsize))
    }
    
    guard let symtab_cmd else { throw SymbolErr.noSymbol }
    
    var stroff: UInt64 = 0
    var symoff: UInt64 = 0
    var linkBase: UInt64 = 0
    
    // Second iteration: Resolve offsets by segments
    for _ in 0..<machHeader.ncmds {
        let load_command = command.assumingMemoryBound(to: load_command.self).pointee
        
        if load_command.cmd == LC_SEGMENT_64 {
            let segment_command = command.assumingMemoryBound(to: segment_command_64.self).pointee
            
            let segnameString = withUnsafeBytes(of: segment_command.segname) { raw in
                String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
                                   
            if linkBase == 0 && segnameString == "__TEXT" {
                linkBase = segment_command.vmaddr
            } else if segnameString == "__LINKEDIT" {
                                
                if (UInt64(symtab_cmd.symoff) - segment_command.fileoff) < segment_command.filesize {
                    symoff = segment_command.vmaddr + UInt64(symtab_cmd.symoff) - segment_command.fileoff
                }
                
                if (UInt64(symtab_cmd.stroff) - segment_command.fileoff) < segment_command.filesize {
                    stroff = segment_command.vmaddr + UInt64(symtab_cmd.stroff) - segment_command.fileoff
                }
                
            }
            
            if stroff != 0 && symoff != 0 && linkBase != 0 {
                break
            }
        }
        
        command = command.advanced(by: Int(load_command.cmdsize))
    }

    guard stroff>0 && symoff>0 else {
        throw SymbolErr.noSymbol
    }
            
    if linkBase != 0 {
        stroff = stroff - linkBase
        symoff = symoff - linkBase
    }
            
    let strTab = machHeaderPointer
        .advanced(by: Int(stroff))
                    
    // Iterate over the load commands
    for idx in 0..<(symtab_cmd.nsyms) { // idk why but the last symbols are always invalid
        
        let symbol = machHeaderPointer
            .advanced(by: Int(symoff))
            .advanced(by: Int(idx) * MemoryLayout<nlist_64>.size)
            .assumingMemoryBound(to: nlist_64.self).pointee
        
        // Access the properties of the symbol structure
        let strIndex = symbol.n_un.n_strx
                
        if strIndex >= symtab_cmd.strsize || strIndex == 0 {
            continue;
        }
        
        // Get the symbol's name from the string table
        let name = strTab.advanced(by: Int(strIndex)).assumingMemoryBound(to: CChar.self)
                    
        guard symbol.n_type != 115 && symbol.n_type != 17 else {
            continue
        }
                             
        if strcmp(name, symbolName) == 0 {
            
            guard symbol.n_value != 0 && symbol.n_value >= linkBase else {
                throw SymbolErr.noAddress
            }

            guard let target = UnsafeMutableRawPointer(bitPattern: UInt(bitPattern: machHeaderPointer.advanced(by: Int(symbol.n_value - linkBase)))) else {
                return nil
            }

            // Match dlsym: only PAC-sign when the target is code in an arm64e image.
            // According to the Substrate specification, the returned function pointer should be directly callable, so we must sign it if it is code: https://www.cydiasubstrate.com/api/c/MSFindSymbol
            if symbolTargetIsCode(image: machHeaderPointer, vmaddr: symbol.n_value) {
                return UnsafeRawPointer(target.makeCallable())
            }
            return UnsafeRawPointer(target)
        }
    }

    throw SymbolErr.noSymbol
}
