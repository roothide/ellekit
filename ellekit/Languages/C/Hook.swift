
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

#if SWIFT_PACKAGE
import ellekitc
#endif

private var hookMutex: pthread_mutex_t = {
    var attr = pthread_mutexattr_t()
    pthread_mutexattr_init(&attr)
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)

    var mutex = pthread_mutex_t()
    pthread_mutex_init(&mutex, &attr)
    pthread_mutexattr_destroy(&attr)
    return mutex
}()

private func debugInstructions(at pointer: UnsafeMutableRawPointer, count: Int) -> String {
    guard count > 0 else { return "[]" }

    let words = pointer.withMemoryRebound(to: UInt32.self, capacity: count) { ptr in
        (0..<count).map { idx in
            String(format: "0x%08x", ptr[idx])
        }
    }

    return "[" + words.joined(separator: ", ") + "]"
}

private func debugBytes(_ pointer: UnsafePointer<UInt8>?, count: Int, limit: Int = 64) -> String {
    guard let pointer, count > 0 else { return "nil" }

    let byteCount = min(count, limit)
    let bytes = (0..<byteCount).map { idx in
        String(format: "%02x", pointer[idx])
    }.joined(separator: " ")

    if count > limit {
        return "\(bytes) ... (\(count) bytes)"
    }

    return "\(bytes) (\(count) bytes)"
}

private func debugMachError(_ kr: kern_return_t) -> String {
    guard let message = mach_error_string(kr) else {
        return "unknown"
    }
    return String(cString: message)
}

@_cdecl("EKHookFunction")
public func hook(_ stockTarget: UnsafeMutableRawPointer, _ stockReplacement: UnsafeMutableRawPointer, _ result: UnsafeMutablePointer<UnsafeMutableRawPointer?>? = nil)
{
    pthread_mutex_lock(&hookMutex)
    defer {
        pthread_mutex_unlock(&hookMutex)
    }

    /*
    guard isDebugged() else {
        var orig: UnsafeMutableRawPointer? = nil
        hardwareHook(stockTarget, stockReplacement, &orig)
        return orig
    }
     */
    
    let target = stockTarget.makeReadable()
    let replacement = stockReplacement.makeReadable()
    print("[*] ellekit: hook request stockTarget=\(stockTarget) target=\(target) stockReplacement=\(stockReplacement) replacement=\(replacement) resultRequested=\(result != nil)")
    
#if DEBUG
    var info = Dl_info()
    dladdr(target, &info)
    if let name = info.dli_sname, let frame = info.dli_fname {
        print("[*] ellekit: hooking \(String(describing: target))/\(String(cString: name)) in \(String(cString: frame)) -> \(String(describing: replacement))/\(info.dli_sname == nil ? "" : String(cString: info.dli_sname))")
    }
#endif
    
    let existingReplacement: UnsafeMutableRawPointer? = withHooksLock { hooks in
        let existing = hooks[target]
        if existing == nil {
            hooks[target] = replacement
        }
        return existing
    }

    if let existingReplacement {
        print("[*] ellekit: chaining existing hook target=\(target) existingReplacement=\(existingReplacement) newReplacement=\(replacement) resultRequested=\(result != nil)")
        return hook(existingReplacement.makeReadable(), replacement, result)
    }

    var patchSize: Int = -1
    var patchCode = [UInt8]()

    var nearbyTramp: NearbyTrampoline? = nil

    let branchOffset = Int(UInt(bitPattern: replacement)) - Int(UInt(bitPattern: target))
    let adrpPageOffset = (Int(UInt(bitPattern: replacement)) & ~0xFFF) - (Int(UInt(bitPattern: target)) & ~0xFFF)
    
    let targetSize = getSafeRebindSize(target, desiredSize: 4)
    
    let directBranchReachable = branchOffset >= -0x800_0000 && branchOffset <= 0x7FF_FFFC
    print("[*] ellekit: branch analysis target=\(target) targetSize=\(targetSize) replacement=\(replacement) branchOffset=\(branchOffset) directBranchReachable=\(directBranchReachable) adrpPageOffset=\(adrpPageOffset)")

    if !directBranchReachable {
        print("[*] ellekit: direct branch out of range; trying nearby stub target=\(target) replacement=\(replacement)")
        if let stub = NearbyTrampoline(base: target, target: replacement, maxPatchSize: targetSize) {
            patchCode = stub.patchCode
            patchSize = stub.patchSize
            nearbyTramp = stub
        } else {
            print("[-] ellekit: no nearby stub page usable target=\(target) replacement=\(replacement) targetSize=\(targetSize)")
        }
    }

    if patchSize > 0 {
        // nearby stub already selected above
    } else if directBranchReachable && targetSize >= 1 { // fastest and simplest branch
        print("[*] ellekit: Small branch")
        @InstructionBuilder
        var codeBuilder: [UInt8] {
            b(branchOffset)
        }
        patchCode = codeBuilder
        patchSize = 1

    } else if targetSize >= 3 && adrpPageOffset >= -0x1_0000_0000 && adrpPageOffset <= 0xFFFF_F000 {
        print("[*] adrp branch")

        let replacementLow16 = Int(UInt(bitPattern: replacement)) & 0xFFFF
        @InstructionBuilder
        var codeBuilder: [UInt8] {
            adrp(.x16, adrpPageOffset)
            movk(.x16, replacementLow16)
            br(.x16)
        }
        patchCode = codeBuilder
        patchSize = 3

    } else if targetSize >= 4 {
        print("[*] Big branch")

        let target_addr = UInt64(UInt(bitPattern: replacement))

        patchCode = [0x50, 0x00, 0x00, 0x58] + // ldr x16, #8
                    br(.x16).bytes() +
                    split(from: target_addr)

        patchSize = 4

    } else if targetSize >= 1, let tramp = Trampoline(base: target, target: replacement) {
        print("[+] ellekit: using trampoline method target=\(target) replacement=\(replacement) trampoline=\(tramp.trampoline) targetSize=\(targetSize)")

        let trampOffset = Int(UInt(bitPattern: tramp.trampoline)) - Int(UInt(bitPattern: target))
        @InstructionBuilder
        var codeBuilder: [UInt8] {
            b(trampOffset)
        }
        patchCode = codeBuilder
        patchSize = 1

    } else { // tiny function beyond b range... using exception handler

        print("ellekit: no hook strategy available target=\(target) replacement=\(replacement) targetSize=\(targetSize) branchOffset=\(branchOffset) adrpPageOffset=\(adrpPageOffset) directBranchReachable=\(directBranchReachable)")

        abort(); //should never happen

//        if exceptionHandler == nil {
//            exceptionHandler = .init()
//        }
//        print("[*] ellekit: using exception handler method")
//        patchCode = [0x20, 0x00, 0x20, 0xD4] // brk #1
//
//        patchSize = 1
    }

    assert(patchCode.count == (patchSize*4))
    guard targetSize > 0 && targetSize >= patchSize else {
        print("ellekit: selected patch has no matching safe size target=\(target) replacement=\(replacement) patchSize=\(patchSize) targetSize=\(targetSize)")
        abort()
    }

    print("[*] ellekit: selected patch target=\(target) replacement=\(replacement) targetSize=\(targetSize) patchSize=\(patchSize) patchCodeBytes=\(patchCode.count) resultRequested=\(result != nil)")

    if let result = result {
        // Intentional force unwrap: requesting `result` means the caller requires an
        // orig function. If orig generation fails, trapping here is the designed behavior.
        
        let (origFunc, origSize) = getOriginal(target, targetSize, codePlacement: nearbyTramp?.freeSpace) ?? (nil, 0)
        
        print("[*] ellekit: getOriginal result target=\(target) targetSize=\(targetSize) origFunc=\(String(describing: origFunc)) origSize=\(origSize)")

        guard let orig = origFunc else {
            print("[-] ellekit: fatal orig is nil target=\(target) replacement=\(replacement) resultStorage=\(result) targetSize=\(targetSize) patchSize=\(patchSize) patchCodeBytes=\(patchCode.count) firstInstructions=\(debugInstructions(at: target, count: 8))")
            
            abort()
        }
        
        result.pointee = orig.makeCallable()
    }
    
    nearbyTramp?.finalize()
    
    let codesize = mach_vm_size_t(MemoryLayout<UInt8>.stride * patchCode.count)

    let ret = patchCode.withUnsafeBufferPointer { buf in
        return rawHook(address: target, code: buf.baseAddress, size: codesize)
    }
    
    if ret != 0 {
        print("ellekit: rawHook failed(\(ret)) target=\(target) replacement=\(replacement) patchSize=\(patchSize) codeSize=\(codesize)")
        abort() //should never happen
    }
}

func split(from uint64: UInt64) -> [UInt8] {
    var result = [UInt8]()
    
    for i in 0..<8 {
        let byte = UInt8((uint64 >> (i * 8)) & 0xFF)
        result.append(byte)
    }
    
    return result
}

@discardableResult @_optimize(speed)
func rawHook(address: UnsafeMutableRawPointer, code: UnsafePointer<UInt8>?, size: mach_vm_size_t) -> Int {
    
    //NSLog("[hookinfo] patching \(String(describing: address)) with \(code == nil ? "nothing!" : Array(UnsafeBufferPointer(start: code, count: Int(size))).map {String(format: "%02X", $0)}.joined())")

    let threads = stopAllThreads()
    print("[*] ellekit: rawHook start address=\(address) size=\(size) code=\(debugBytes(code, count: Int(size))) stoppedThreads=\(threads.count)")
    defer {
        resumeAllThreads(threads)
    }
    
    let goodSize = Int(size)
    let machAddr = mach_vm_address_t(UInt(bitPattern: address))
            
    let krt1 = custom_mach_vm_protect(
        mach_task_self_,
        machAddr,
        size,
        0,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY
    )
        
    guard krt1 == KERN_SUCCESS else {
        print("[-] ellekit: rawHook failed to set RW protection err=\(krt1) message=\(debugMachError(krt1)) address=\(address) size=\(size)")
        return Int(krt1)
    }

    manual_memcpy(address, code, goodSize)
        
    // This might fail if developer mode is not enabled.
    let err2 = custom_mach_vm_protect(
        mach_task_self_,
        machAddr,
        size,
        0,
        VM_PROT_READ | VM_PROT_EXECUTE
    )

    guard err2 == KERN_SUCCESS else {
        // This shouldn't happen; if it fails here, the process is corrupted because we can't recover the previous executable page.
        print("ellekit: failed to restore RX protection err=\(err2) message=\(debugMachError(err2)) address=\(address) size=\(size)")
        abort()
    }

    // flush page cache so we don't hit cached unpatched functions
    sys_icache_invalidate(address, Int(size))
               
    return 0
}
