
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

#if SWIFT_PACKAGE
import ellekitc
#endif

private func debugBytes(_ bytes: [UInt8], limit: Int = 64) -> String {
    let prefix = bytes.prefix(limit).map { String(format: "%02x", $0) }.joined(separator: " ")
    if bytes.count > limit {
        return "\(prefix) ... (\(bytes.count) bytes)"
    }
    return "\(prefix) (\(bytes.count) bytes)"
}

private func debugInstructionWords(_ bytes: [UInt8]) -> String {
    guard !bytes.isEmpty else { return "[]" }

    var words = [String]()
    var idx = 0
    while idx + 3 < bytes.count {
        let word = UInt32(bytes[idx]) | (UInt32(bytes[idx + 1]) << 8) | (UInt32(bytes[idx + 2]) << 16) | (UInt32(bytes[idx + 3]) << 24)
        words.append(String(format: "0x%08x", word))
        idx += 4
    }

    if idx < bytes.count {
        words.append("trailing=\(debugBytes(Array(bytes[idx...])))")
    }

    return "[" + words.joined(separator: ", ") + "]"
}

private func debugMachError(_ kr: kern_return_t) -> String {
    guard let message = mach_error_string(kr) else {
        return "unknown"
    }
    return String(cString: message)
}

/// If the first instruction in `bytes` is an unconditional branch (B imm, bits[31:26] == 000101),
/// returns its raw instruction word so it can be redirected straight to its destination; otherwise nil.
/// Caller must ensure `bytes` holds at least one instruction (4 bytes) before calling.
private func unconditionalBranchInstruction(_ bytes: [UInt8]) -> UInt64? {
    let isn = UInt64(combine(bytes))
    guard reverse(UInt32(isn)) >> 26 == b.base >> 26 else { return nil }
    return isn
}

// PAC: strip before calling this function and sign the result afterwards
func getOriginal(_ target: UnsafeMutableRawPointer, _ rebindSize: Int, codePlacement: (address: UnsafeMutableRawPointer, capacity: Int)? = nil) -> (UnsafeMutableRawPointer, Int)?
{
    guard rebindSize > 0 else {
        print("[-] ellekit: getOriginal failed because rebindSize <= 0 target=\(target) rebindSize=\(rebindSize)")
        return nil
    }

    let safeReg = findSafeRegister(target, isns: rebindSize)
    let tmpReg = Register.x(safeReg)
    print("[*] ellekit: getOriginal safeReg=x\(safeReg) target=\(target) rebindSize=\(rebindSize)")

    let rebindCodeSize = rebindSize * 4

    var unpatched = target.withMemoryRebound(to: UInt8.self, capacity: rebindCodeSize, { ptr in
        Array(UnsafeMutableBufferPointer(start: ptr, count: rebindCodeSize))
    })
    print("[*] ellekit: getOriginal start target=\(target) rebindSize=\(rebindSize) tmpReg=\(tmpReg) originalInstructions=\(debugInstructionWords(unpatched))")
        
    let target_addr = UInt64(UInt(bitPattern: target))

    let ptr: UnsafeMutableRawPointer
    let capacity: Int
    let ownsMemory: Bool

    if let codePlacement {
        ptr = codePlacement.address
        capacity = codePlacement.capacity
        ownsMemory = false
        print("[*] ellekit: getOriginal using provided code placement target=\(target) ptr=\(ptr) capacity=\(capacity)")
    } else {
        var allocated: mach_vm_address_t = 0
        let allocKr = mach_vm_allocate(mach_task_self_, &allocated, UInt64(vm_page_size), VM_FLAGS_ANYWHERE)
        guard allocKr == KERN_SUCCESS else {
            print("[-] ellekit: getOriginal mach_vm_allocate failed target=\(target) rebindSize=\(rebindSize) err=\(allocKr) message=\(debugMachError(allocKr))")
            return nil
        }

        guard let allocatedPtr = UnsafeMutableRawPointer(bitPattern: UInt(allocated)) else {
            print("[-] ellekit: getOriginal allocated null pointer target=\(target) address=0x\(String(allocated, radix: 16))")
            return nil
        }
        ptr = allocatedPtr
        capacity = Int(vm_page_size)
        ownsMemory = true
        print("[*] ellekit: getOriginal allocated orig page target=\(target) ptr=\(ptr)")
    }

    var code = [UInt8]()

    // Special case: a single instruction that is an unconditional branch.
    // Redirect straight to the branch's destination; no relocated prologue or trailing jump-back needed.
    // (rebindSize == 1 short-circuits before the decode, so unpatched always has 4 bytes here.)
    if rebindSize == 1, let branchInsn = unconditionalBranchInstruction(unpatched) {
        print("[*] ellekit: getOriginal redirecting single branch target=\(target) branchInsn=0x\(String(branchInsn, radix: 16)) ptr=\(ptr)")
        code = redirectBranch(target, branchInsn, ptr, jmpReg: tmpReg)
    } else {
        // Relocate the copied prologue, then jump back past it to target + rebindCodeSize.
        // (chunked(into: 4) yields a single instruction when rebindSize == 1, so this also
        // covers the old "Small function" non-branch path.)
        unpatched = unpatched.chunked(into: 4).rebind(
            formerPC: UInt64(UInt(bitPattern: target)),
            newPC: UInt64(UInt(bitPattern: ptr)),
            tmpReg: tmpReg
        )

        code = unpatched
        code += assembleJump(
            target_addr &+ UInt64(rebindCodeSize),
            pc: UInt64(UInt(bitPattern: ptr)) &+ UInt64(code.count),
            link: false,
            big: true,
            jmpReg: tmpReg
        )
    }

    let codesize = code.count
    print("[*] ellekit: getOriginal generated code target=\(target) ptr=\(ptr) codesize=\(codesize) code=\(debugBytes(code))")

    let pageBase = mach_vm_address_t(UInt(bitPattern: ptr) & ~UInt(vm_page_size - 1))

    guard codesize <= capacity else {
        print("[-] ellekit: orig code (\(codesize) bytes) exceeds capacity (\(capacity)) target=\(target) ptr=\(ptr)")
        if ownsMemory { mach_vm_deallocate(mach_task_self_, pageBase, UInt64(vm_page_size)) }
        abort()
    }

    memcpy(ptr, code, codesize)

    // Self-allocated page: seal RX + icache here. External placement (e.g. nearby
    // freeSpace) stays RW until the caller's finalize(); page must already be writable.
    if ownsMemory {
        // This might fail if developer mode is not enabled.
        let rxKr = mach_vm_protect(mach_task_self_, pageBase, UInt64(vm_page_size), 0, VM_PROT_READ | VM_PROT_EXECUTE)
        guard rxKr == KERN_SUCCESS else {
            print(["[-] ellekit: couldn't vm_protect orig page to RX:", debugMachError(rxKr)])
            mach_vm_deallocate(mach_task_self_, pageBase, UInt64(vm_page_size))
            abort()
        }
        sys_icache_invalidate(UnsafeMutableRawPointer(bitPattern: UInt(pageBase))!, Int(vm_page_size))
    }

    print(["[+] ellekit: Orig written to:", ptr])
    return (ptr, codesize)
}
