
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

#if SWIFT_PACKAGE
import ellekitc
#endif

private func nearbyMachError(_ kr: kern_return_t) -> String {
    guard let message = mach_error_string(kr) else {
        return "unknown"
    }
    return String(cString: message)
}

/// Branch stub in a freshly allocated page within range of `base`.
///
/// Page layout: `[0, jumpStubSize)` jump stub; `[jumpStubSize, pageSize)` exposed as
/// `freeSpace` for `getOriginal`.
///
/// Lifecycle:
/// 1. `init` — map page RW, emit jump stub, derive entry patch for `base`
/// 2. `getOriginal(..., codePlacement: freeSpace)` — write orig into the page tail
/// 3. `finalize()` — map page RX, invalidate icache (before control may enter stub)
struct NearbyTrampoline
{
    /// Bytes to overwrite at the hooked entry (`base`).
    let patchCode: [UInt8]
    /// Instruction count in `patchCode` (always <= `maxPatchSize`).
    let patchSize: Int

    /// Free space on the trampoline page after the jump stub.
    let freeSpace: (address: UnsafeMutableRawPointer, capacity: Int)

    private let trampolinePage: UnsafeMutableRawPointer

    /// `maxPatchSize` — safe rebind prefix at `base`, in **instructions**
    /// (same unit as `getSafeRebindSize` / `getOriginal(..., rebindSize:)`).
    ///
    /// Strategy: ±128 MiB page + single `b` (needs 1); else ±4 GiB + `adrp`/`br` (needs 2).
    init?(
        base: UnsafeMutableRawPointer,
        target: UnsafeMutableRawPointer,
        maxPatchSize: Int
    ) {
        print("[*] ellekit: nearby stub attempt base=\(base) target=\(target) maxPatchSize=\(maxPatchSize)")

        if maxPatchSize >= 1, let page = allocateNearbyPage(near: base, maxDistance: 0x7FF_FFFC) {
            let stubSize = writeJumpStub(at: page, destination: target)
            let stubOffset = Int(UInt(bitPattern: page)) - Int(UInt(bitPattern: base))

            print("[*] ellekit: nearby stub (b) at \(page)")
            @InstructionBuilder
            var codeBuilder: [UInt8] {
                b(stubOffset)
            }
            self.patchCode = codeBuilder
            self.patchSize = 1
            self.trampolinePage = page
            self.freeSpace = (page + stubSize, Int(vm_page_size) - stubSize)
            return
        }

        if maxPatchSize >= 2, let page = allocateNearbyPage(near: base, maxDistance: 0xFFFF_F000) {
            let stubSize = writeJumpStub(at: page, destination: target)

            print("[*] ellekit: nearby stub (adrp+br) at \(page)")
            let basePage = UInt64(UInt(bitPattern: base)) & ~0xFFF
            let trampPageAddr = UInt64(UInt(bitPattern: page))
            @InstructionBuilder
            var codeBuilder: [UInt8] {
                adrp(.x16, Int(Int64(trampPageAddr) - Int64(basePage)))
                br(.x16)
            }
            self.patchCode = codeBuilder
            self.patchSize = 2
            self.trampolinePage = page
            self.freeSpace = (page + stubSize, Int(vm_page_size) - stubSize)
            return
        }

        print("[-] ellekit: no nearby stub page usable base=\(base) target=\(target) maxPatchSize=\(maxPatchSize)")
        return nil
    }

    /// Complete stub installation: RW → RX, `sys_icache_invalidate`.
    /// Must run after all stub writes and before `base` is patched to branch here.
    func finalize() {
        let kr = custom_mach_vm_protect(
            mach_task_self_,
            mach_vm_address_t(UInt(bitPattern: trampolinePage)),
            mach_vm_size_t(vm_page_size),
            0,
            VM_PROT_READ | VM_PROT_EXECUTE
        )
        guard kr == KERN_SUCCESS else {
            print("ellekit: nearby stub finalize failed err=\(kr) trampolinePage=\(trampolinePage) message=\(nearbyMachError(kr))")
            abort()
        }
        sys_icache_invalidate(trampolinePage, Int(vm_page_size))
    }
}

private func writeJumpStub(at page: UnsafeMutableRawPointer, destination: UnsafeMutableRawPointer) -> Int {
    let destAddr = UInt64(UInt(bitPattern: destination))
    let stubCode = [0x50, 0x00, 0x00, 0x58] + // ldr x16, #8
                   br(.x16).bytes() +
                   split(from: destAddr)

    _ = stubCode.withUnsafeBufferPointer { buf in
        memcpy(page, buf.baseAddress!, buf.count)
    }

    return stubCode.count
}

/// Allocate a page-aligned memory region near `target` within `maxDistance` bytes.
///
/// `mmap(MAP_ANON)` routes through libc's anonymous arena and effectively ignores the
/// address hint, so it can only ever hand back pages in the data region — far from a
/// function that lives in the dyld shared cache. `mach_vm_map` with `VM_FLAGS_ANYWHERE`
/// instead honours the hint as a real search start: it scans *upward only* (no wraparound)
/// and returns `KERN_NO_SPACE` if nothing is free above the hint.
///
/// Because the scan is upward-only, a single hint at the low edge of the window
/// (`target - maxDistance`) sweeps the entire reachable range `[target - maxDistance,
/// target + maxDistance]` in one pass — it finds the lowest free hole, whether it sits
/// below or above `target`. A hint at `target` itself would miss every hole below it, so
/// the low-edge hint is strictly better and a second hint is unnecessary.
private func allocateNearbyPage(near target: UnsafeMutableRawPointer, maxDistance: Int) -> UnsafeMutableRawPointer? {
    let pageSize = Int(vm_page_size)
    let pageMask = UInt(pageSize - 1)
    let targetAddr = UInt(bitPattern: target)
    let distance = UInt(maxDistance)

    let lowerBound = targetAddr > distance ? targetAddr - distance : 0
    var hint = mach_vm_address_t((lowerBound + pageMask) & ~pageMask)

    let kr = mach_vm_map(
        mach_task_self_,
        &hint,
        mach_vm_size_t(pageSize),
        0,
        VM_FLAGS_ANYWHERE,
        0,
        0,
        0,
        VM_PROT_READ | VM_PROT_WRITE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        VM_INHERIT_DEFAULT
    )

    guard kr == KERN_SUCCESS else {
        print("[-] ellekit: allocateNearbyPage mach_vm_map failed target=\(target) maxDistance=\(maxDistance) hint=0x\(String(lowerBound, radix: 16)) err=\(kr) message=\(nearbyMachError(kr))")
        return nil
    }

    let allocAddr = UInt(hint)
    let dist = allocAddr > targetAddr ? allocAddr - targetAddr : targetAddr - allocAddr
    guard dist <= distance, let ptr = UnsafeMutableRawPointer(bitPattern: allocAddr) else {
        print("[-] ellekit: allocateNearbyPage out of range target=\(target) maxDistance=\(maxDistance) ptr=0x\(String(allocAddr, radix: 16)) dist=\(dist)")
        mach_vm_deallocate(mach_task_self_, hint, mach_vm_size_t(pageSize))
        return nil
    }

    print("[*] ellekit: allocateNearbyPage accepted target=\(target) maxDistance=\(maxDistance) ptr=\(ptr) dist=\(dist)")
    return ptr
}
