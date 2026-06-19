
import Foundation

#if SWIFT_PACKAGE
import ellekitc
#endif

public func sharedCachePath() -> String {
    #if os(macOS)
    if #available(macOS 13.0, *) {
        #if arch(arm64)
        return "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
        #elseif arch(x86_64)
        return "/System/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64"
        #endif
    } else {
        #if arch(arm64)
        return "/System/Library/dyld/dyld_shared_cache_arm64e"
        #elseif arch(x86_64)
        return "/System/Library/dyld/dyld_shared_cache_x86_64"
        #endif
    }
    #else
    if #available(iOS 16.0, *) {
        if FileManager.default.fileExists(atPath: "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e") {
            return "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e"
        } else {
            return "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
        }
    } else {
        if FileManager.default.fileExists(atPath: "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e") {
            return "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e"
        } else {
            return "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
        }
    }
    #endif
}

private func sharedCacheSymbolsPath() -> String {
    if #available(iOS 15.0, watchOS 8.0, tvOS 15.0, *) {
        return sharedCachePath()+".symbols"
    } else {
        return sharedCachePath()
    }
}

typealias FileHandleC = UnsafeMutablePointer<FILE>
extension FileHandleC {
    @inline(__always)
    func readData(ofLength count: Int) -> UnsafeMutableRawPointer {
        let alloc = malloc(count)
        let read = fread(alloc, 1, count, self)
        assert(read == count)
        return alloc!
    }
    
    @discardableResult @inline(__always)
    func seek(toFileOffset offset: UInt64) -> UnsafeMutablePointer<FILE> {
        var pos: fpos_t = .init(offset)
        fsetpos(self, &pos)
        return self
    }
    
    @inline(__always)
    var offsetInFile: UInt64 {
        var pos: fpos_t = 0
        fgetpos(self, &pos)
        return .init(pos)
    }
    
    @inline(__always)
    func close() {
        fclose(self)
    }
}

func getImageLinkBase(image machHeaderPointer: UnsafeRawPointer) -> UInt64 {
    
    let machHeader = machHeaderPointer
        .assumingMemoryBound(to: mach_header_64.self)
        .pointee
    
    var linkBase: UInt64 = 0
    
    // Read the load commands
    var command = machHeaderPointer.advanced(by: MemoryLayout<mach_header_64>.size)
    
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
                break
            }
        }
        
        command = command.advanced(by: Int(load_command.cmdsize))
    }
    
    return linkBase
}

public func findPrivateSymbol(
    image machHeaderPointer: UnsafeRawPointer,
    symbol symbolName: String,
    overrideCachePath: String? = nil
) throws -> UnsafeRawPointer? {
    
    guard let handle = fopen(overrideCachePath ?? sharedCacheSymbolsPath(), "r") else {
        print("[-] ellekit: failed to open shared cache")
        throw SymbolErr.badCachePath
    }
    
    defer { handle.close() }
                    
    let entryPtr = handle
        .readData(ofLength: MemoryLayout<dyld_cache_header>.size)
        .assumingMemoryBound(to: dyld_cache_header.self)
    
    let entry = entryPtr.pointee
            
    handle.seek(toFileOffset: entry.localSymbolsOffset)
    
    free(entryPtr)
    
    let symInfoPtr = handle
        .readData(ofLength: MemoryLayout<dyld_cache_local_symbols_info>.size)
        .assumingMemoryBound(to: dyld_cache_local_symbols_info.self)

    var symInfo = symInfoPtr.pointee
    
    free(symInfoPtr)
        
    handle.seek(toFileOffset: entry.localSymbolsOffset + UInt64(symInfo.entriesOffset))
    
    var check: UInt64 = 0
    
    shared_region_check(&check)
    
    var inSharedCache = false
                    
    for _ in 0..<symInfo.entriesCount {
        let entryPtr = handle
            .readData(ofLength: MemoryLayout<dyld_cache_local_symbols_entry>.size)
            .assumingMemoryBound(to: dyld_cache_local_symbols_entry.self)

        defer { free(entryPtr) }

        let entry = entryPtr.pointee

        if UnsafeRawPointer(bitPattern: UInt(check + entry.dylibOffset)) == machHeaderPointer {
            symInfo.nlistOffset = entry.nlistStartIndex * UInt32(MemoryLayout<nlist_64>.size) + symInfo.nlistOffset
            symInfo.nlistCount = entry.nlistCount
            inSharedCache = true
            break
        }
    }
    
    guard inSharedCache else { return nil }
    
    let linkBase = getImageLinkBase(image: machHeaderPointer)
    
    let strTab = entry.localSymbolsOffset + UInt64(symInfo.stringsOffset)
                    
    handle.seek(toFileOffset: entry.localSymbolsOffset + UInt64(symInfo.nlistOffset))
        
    let cSymbolName: UnsafeMutablePointer<CChar> = strdup(symbolName)
    let cSymbolNameLength = strlen(cSymbolName)
    defer { free(cSymbolName) }
    
    for idx in 0..<(symInfo.nlistCount) {
                        
        let symbolPtr = handle
            .seek(toFileOffset: UInt64(entry.localSymbolsOffset + UInt64(symInfo.nlistOffset)) + UInt64(idx) * UInt64(MemoryLayout<nlist_64>.size))
            .readData(ofLength: MemoryLayout<nlist_64>.size)
            .assumingMemoryBound(to: nlist_64.self)
        
        let symbol = symbolPtr.pointee
                        
        defer { free(symbolPtr) }
                
        guard symbol.n_un.n_strx != 0 && symbol.n_value != 0 && symbol.n_value >= linkBase && symbol.n_type != 115 && symbol.n_type != 17 else {
            continue
        }
                
        // Get the symbol's name from the string table
        let name = handle
            .seek(toFileOffset: strTab + UInt64(symbol.n_un.n_strx))
            .readData(ofLength: cSymbolNameLength + 1)
            .assumingMemoryBound(to: CChar.self)
                
        defer {
            free(name)
        }
                        
        if strncmp(name, cSymbolName, cSymbolNameLength) == 0 && name[cSymbolNameLength] == 0 {
            guard let target = UnsafeMutableRawPointer(bitPattern: UInt(bitPattern: machHeaderPointer.advanced(by: Int(symbol.n_value - linkBase)))) else {
                return nil
            }

            // Match dlsym: only PAC-sign when the target is code in an arm64e image.
            if symbolTargetIsCode(image: machHeaderPointer, vmaddr: symbol.n_value) {
                return UnsafeRawPointer(target.makeCallable())
            }
            return UnsafeRawPointer(target)
        }
    }
    
    return nil
}

