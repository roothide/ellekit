
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

public struct Trampoline {
    var base: UnsafeMutableRawPointer
    var target: UnsafeMutableRawPointer

    /// The address `base` should branch to. This may be a header-padding stub, or the borrowed
    /// function's entry + 16 when using the victim-function fallback.
    public var trampoline: UnsafeMutableRawPointer = UnsafeMutableRawPointer(bitPattern: -2)!

    // Sets up a nearby trampoline address for `base` to branch to. Header padding is preferred
    // because it does not borrow another function; if that fails, fall back to a victim function.
    // The caller patches `base` and produces `base`'s orig via hook()'s shared tail.
    // PAC: strip before initializing
    public init?(base: UnsafeMutableRawPointer, target: UnsafeMutableRawPointer) {

        // #if DEBUG
        // #else
        // return nil;
        // #endif

        // var info = Dl_info()
        // dladdr(base, &info)

        // if #available(iOS 9999.0, macOS 11.0, *) {
        //     if info.dli_fname != nil && _dyld_shared_cache_contains_path(info.dli_fname) {
        //         print("in dyld cache")
        //     } else {
        //         return nil
        //     }
        // } else {
        //     return nil
        // }

        // stopAllThreads()

        // defer { resumeAllThreads() }

        self.base = base
        self.target = target
        print("[*] trampoline: init base=\(base) target=\(target)")

        if let headerStub = self.findHeaderStub(near: base, size: 16)
        {
            print("[*] trampoline: header candidate base=\(base) target=\(target) headerStub=\(headerStub)")
            if self.buildHeaderTrampoline(at: headerStub)
            {
                self.trampoline = headerStub
                
                return
            }
            print("[-] trampoline: header candidate write failed base=\(base) target=\(target) headerStub=\(headerStub)")
        } else {
            print("[-] trampoline: no header candidate base=\(base) target=\(target)")
        }

        if let (location, size) = self.findVictimFunction(size: 8)
        {
            print("[*] trampoline: victim candidate base=\(base) target=\(target) location=\(location) size=\(size)")
            if let orig = self.buildVictimTrampoline(at: location, size: size)
            {
                self.trampoline = location.advanced(by: 16)
                
                withHooksLock { hooks in
                    hooks[location] = orig
                }
                
                return
            }
            print("[-] trampoline: victim build failed base=\(base) target=\(target) location=\(location) size=\(size)")
        }
        
        print("[-] trampoline: init failed base=\(base) target=\(target)")
        return nil
    }

    private func buildHeaderTrampoline(at headerStub: UnsafeMutableRawPointer) -> Bool
    {
        let targetAddr = UInt64(UInt(bitPattern: target))
        let code = [0x50, 0x00, 0x00, 0x58] + // ldr x16, #8
                   br(.x16).bytes() +
                   split(from: targetAddr)
        let writeSize = mach_vm_size_t(MemoryLayout<UInt8>.stride * code.count)
        print("[*] trampoline: writing header stub base=\(base) target=\(target) headerStub=\(headerStub) writeSize=\(writeSize)")
        let ret = code.withUnsafeBufferPointer { buf in
            rawHook(address: headerStub, code: buf.baseAddress, size: writeSize)
        }

        guard ret == 0 else {
            print(["[-] trampoline: couldn't write header stub:", String(cString: mach_error_string(kern_return_t(ret)))])
            return false
        }

        print(["[+] trampoline: header stub @", headerStub])
        return true
    }

    // Borrowed-function layout written at `location` (the victim's own entry):
    //   [0,16)  jump to the victim's relocated orig (so the borrowed function still works)
    //   [16,32) jump to `target` (the replacement) — this is what `base` branches to
    // Relocates the victim's prologue into its orig, then writes & activates the 32-byte trampoline.
    // Returns the victim's orig, or nil on failure. (patch is only 32 bytes)
    func buildVictimTrampoline(at location: UnsafeMutableRawPointer, size: Int) -> UnsafeMutableRawPointer?
    {
        print("[*] trampoline: build victim start base=\(base) target=\(target) location=\(location) size=\(size)")
        guard let (orig, _) = getOriginal(
            location, size
        ) else {
            print("[-] trampoline: couldn't get orig for victim function base=\(base) target=\(target) location=\(location) size=\(size)")
            return nil
        }

        let origJump: [UInt8] = [0x50, 0x00, 0x00, 0x58] + // ldr x16, #8
                                br(.x16).bytes() +
                                split(from: UInt64(UInt(bitPattern: orig)))
        
        let targetJump: [UInt8] = [0x50, 0x00, 0x00, 0x58] + // ldr x16, #8
                        br(.x16).bytes() +
                        split(from: UInt64(UInt(bitPattern: target)))
        
        let code: [UInt8] = origJump + targetJump

        let writeSize = mach_vm_size_t(MemoryLayout<UInt8>.stride * code.count)
        print("[*] trampoline: writing victim trampoline base=\(base) target=\(target) location=\(location) writeSize=\(writeSize) orig=\(orig)")
        let ret = code.withUnsafeBufferPointer { buf in
            rawHook(address: location.makeReadable(), code: buf.baseAddress, size: writeSize)
        }

        guard ret == 0 else {
            print("[-] trampoline: couldn't write trampoline base=\(base) target=\(target) location=\(location) ret=\(ret)")
            return nil
        }

        return orig
    }
}
