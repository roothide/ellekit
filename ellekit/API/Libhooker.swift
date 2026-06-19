
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

#if SWIFT_PACKAGE
import ellekitc
#endif

// libhooker API Implementation
// Conforms to the spec from https://libhooker.com

// MARK: - libblackjack

@_cdecl("LBHookMessage")
public func LBHookMessage(_ cls: AnyClass, _ sel: Selector, _ imp: IMP, _ oldptr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> CInt {
    // Mirror libblackjack: report a missing selector instead of silently doing nothing.
    guard class_getInstanceMethod(cls, sel) != nil else {
        return CInt(LIBHOOKER_ERR_SELECTOR_NOT_FOUND.rawValue)
    }
    messageHook(cls, sel, imp, oldptr)
    return CInt(LIBHOOKER_OK.rawValue)
}

// MARK: - libhooker

@_cdecl("LHStrError")
public func LHStrError(_ err: LIBHOOKER_ERR) -> UnsafeRawPointer? {

    var error: String = ""

    switch err.rawValue {
    case 0: error = "No errors took place"
    case 1: error = "An Objective-C selector was not found. (This error is from libblackjack)"
    case 2: error = "A function was too short to hook"
    case 3: error = "A problematic instruction was found at the start. We can't preserve the original function due to this instruction getting clobbered."
    case 4: error = "An error took place while handling memory pages"
    case 5: error = "No symbol was specified for hooking"
    default: error = "Unknown error"
    }

    return UnsafeRawPointer(strdup((error as NSString).utf8String)) // duplicate coz arc
}

@_cdecl("LHPatchMemory")
public func LHPatchMemory(_ patches: UnsafePointer<LHMemoryPatch>, _ count: CInt) -> CInt {
    // Mirror libhooker: return the number of regions successfully patched (== count on
    // full success), and only count a region when the underlying write actually succeeds.
    var successCount: CInt = 0
    for patch in Array(UnsafeBufferPointer(start: patches, count: Int(count))) {
        guard let dest = patch.destination,
              let code = patch.data?.assumingMemoryBound(to: UInt8.self) else {
            continue
        }
        if rawHook(address: dest, code: code, size: mach_vm_size_t(patch.size)) == 0 {
            successCount += 1
        }
    }
    return successCount
}

@_cdecl("LHExecMemory")
public func LHExecMemory(_ page: UnsafeMutablePointer<UnsafeMutableRawPointer?>, _ data: UnsafeMutableRawPointer, _ size: size_t) -> Bool {
    // Round the requested size up to a page boundary. The blob may span more than one
    // page, so the whole region must be allocated and marked executable (mirrors
    // libhooker's mmap(size) + per-page RX); using a fixed single page would overflow
    // the allocation in memcpy and leave trailing pages non-executable.
    let pageSize = UInt64(vm_page_size)
    let allocSize = (UInt64(size) &+ pageSize &- 1) & ~(pageSize &- 1)
    guard allocSize > 0 else { return false }

    var addr: mach_vm_address_t = 0
    let krt1 = mach_vm_allocate(mach_task_self_, &addr, allocSize, VM_FLAGS_ANYWHERE)
    guard krt1 == KERN_SUCCESS else {
        print(["[-] couldn't allocate base memory:", String(cString: mach_error_string(krt1))])
        return false
    }
    let krt2 = mach_vm_protect(mach_task_self_, addr, allocSize, 0, VM_PROT_READ | VM_PROT_WRITE)
    guard krt2 == KERN_SUCCESS else {
        print(["[-] couldn't set memory to rw*:", String(cString: mach_error_string(krt2))])
        mach_vm_deallocate(mach_task_self_, addr, allocSize)
        return false
    }
    memcpy(UnsafeMutableRawPointer(bitPattern: UInt(addr)), data, size)
    let krt3 = mach_vm_protect(mach_task_self_, addr, allocSize, 0, VM_PROT_READ | VM_PROT_EXECUTE)
    guard krt3 == KERN_SUCCESS else {
        print(["[-] couldn't set memory to r*x:", String(cString: mach_error_string(krt3))])
        mach_vm_deallocate(mach_task_self_, addr, allocSize)
        return false
    }
    page.pointee = UnsafeMutableRawPointer(bitPattern: UInt(addr))
    return true
}

@_cdecl("LHHookFunctions")
public func LHHookFunctions(_ allHooks: UnsafePointer<LHFunctionHook>, _ count: CInt) -> CInt {

    let hooksArray = Array(UnsafeBufferPointer(start: allHooks, count: Int(count)))

    // Mirror libhooker: return the number of functions successfully hooked (== count on
    // full success) and surface the last failure through errno. ellekit's hook() aborts
    // on an unrecoverable failure, so any hook that clears the symbol check is a success.
    var successHook: CInt = 0
    errno = 0

    for targetHook in hooksArray {

        guard let target = targetHook.function,
                let replacement = targetHook.replacement else {
            errno = CInt(LIBHOOKER_ERR_NO_SYMBOL.rawValue)
            continue
        }

        let result = targetHook.oldptr?.assumingMemoryBound(to: UnsafeMutableRawPointer?.self)

        hook(target, replacement, result)

        if let orig = result?.pointee {
            print("[+] ellekit: Performed one hook in LHHookFunctions from \(String(describing: target)) with orig at \(String(describing: orig))")
        } else {
            print("[+] ellekit: Performed one hook in LHHookFunctions from \(String(describing: target)) with no orig")
        }

        successHook += 1
    }

    return successHook
}

@_cdecl("LHOpenImage")
public func LHOpenImage(_ path: UnsafePointer<CChar>) -> UnsafePointer<mach_header>? {
    try? ellekit.openImage(image: String(cString: path))
}

@_cdecl("LHCloseImage")
public func LHCloseImage(_ image: UnsafePointer<mach_header>) {
    // no-op
}

@_cdecl("LHFindSymbols")
public func LHFindSymbols(
    _ image: UnsafePointer<mach_header_64>,
    _ search: UnsafePointer<UnsafePointer<CChar>>,
    _ searchSyms: UnsafeMutablePointer<UnsafeRawPointer?>,
    _ searchSymCount: size_t
) -> Bool {
    let search = Array(UnsafeBufferPointer(start: search, count: searchSymCount)).map { String(cString: $0) }
    let found = search.map { MSFindSymbol(image, $0) }
    for sym in 0..<found.count {
        searchSyms[sym] = found[sym]
    }
    return found.compactMap { $0 }.count == searchSymCount
}
