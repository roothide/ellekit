// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

private struct RegisterUse {
    var reads = Set<Int>()
    var writes = Set<Int>()

    mutating func read(_ register: UInt32) {
        guard register != 31 else { return }
        reads.insert(Int(register))
    }

    mutating func write(_ register: UInt32) {
        guard register != 31 else { return }
        writes.insert(Int(register))
    }
}

func findSafeRegister(_ fn: UnsafeMutableRawPointer, isns: Int) -> Int {
    let candidates = [17, 16, 15, 14, 13, 12, 11, 10, 9]
    if isns <= 0 {
        print("[-] ellekit: findSafeRegister called with no instructions fn=\(fn) isns=\(isns); using first available candidate")
    }

    let instructions: [UInt32] = fn.withMemoryRebound(to: UInt32.self, capacity: isns) { ptr in
        Array(UnsafeMutableBufferPointer(start: ptr, count: isns))
    }

    var touched = Set<Int>()

    for instruction in instructions.reversed() {
        let registerUse = generalRegisterUse(instruction)

        touched.formUnion(registerUse.reads)
        touched.formUnion(registerUse.writes)
    }

    if let register = candidates.first(where: { !touched.contains($0) }) {
        print("[*] ellekit: findSafeRegister fn=\(fn) isns=\(isns) touched=\(touched.sorted()) selected=x\(register)")
        return register
    }
    
    print("ellekit: no safe register found isns=\(isns) touched=\(touched.sorted()) candidates=\(candidates)")
    abort() //should never happen
}

private func generalRegisterUse(_ instruction: UInt32) -> RegisterUse {
    var registerUse = RegisterUse()

    if instruction & 0xFFFFF01F == 0xD503201F {
        return registerUse
    }

    if decodeLoadStore(instruction, into: &registerUse) {
        return registerUse
    }

    if decodeDataProcessingImmediate(instruction, into: &registerUse) {
        return registerUse
    }

    if decodeDataProcessingRegister(instruction, into: &registerUse) {
        return registerUse
    }

    if decodeBranchesAndSystem(instruction, into: &registerUse) {
        return registerUse
    }

    addConservativeRegisterFields(instruction, into: &registerUse)
    return registerUse
}

private func decodeLoadStore(_ instruction: UInt32, into registerUse: inout RegisterUse) -> Bool {
    if instruction & 0x3B000000 == 0x18000000 {
        let isSIMDOrFPLoad = (instruction & 0x04000000) != 0
        if !isSIMDOrFPLoad && instruction & 0xC0000000 != 0xC0000000 {
            registerUse.write(rt(instruction))
        }
        return true
    }

    if instruction & 0x3B000000 == 0x08000000 {
        let isSIMDOrFPLoadStore = (instruction & 0x04000000) != 0
        let isLoad = (instruction & 0x00400000) != 0
        let isPostIndexedSIMDOrFPLoadStore = isSIMDOrFPLoadStore && (instruction & 0x00800000) != 0

        registerUse.read(rn(instruction))
        if isSIMDOrFPLoadStore {
            if isPostIndexedSIMDOrFPLoadStore {
                registerUse.write(rn(instruction))
                registerUse.read(rm(instruction))
            }
        } else if isLoad {
            registerUse.write(rt(instruction))
            registerUse.write(rt2(instruction))
        } else {
            registerUse.read(rt(instruction))
            registerUse.read(rt2(instruction))
            registerUse.write(rs(instruction))
        }
        return true
    }

    if instruction & 0x3A000000 == 0x28000000 {
        let isLoad = (instruction & 0x00400000) != 0
        let isSIMDOrFPLoadStore = (instruction & 0x04000000) != 0
        let addressing = (instruction >> 23) & 0x3
        let isWriteback = addressing == 0b01 || addressing == 0b11

        registerUse.read(rn(instruction))
        if !isSIMDOrFPLoadStore {
            if isLoad {
                registerUse.write(rt(instruction))
                registerUse.write(rt2(instruction))
            } else {
                registerUse.read(rt(instruction))
                registerUse.read(rt2(instruction))
            }
        }

        if isWriteback {
            registerUse.write(rn(instruction))
        }
        return true
    }

    if instruction & 0x3B200C00 == 0x38200800 {
        let isLoad = (instruction & 0x00400000) != 0
        let isSIMDOrFPLoadStore = (instruction & 0x04000000) != 0

        registerUse.read(rn(instruction))
        registerUse.read(rm(instruction))
        if !isSIMDOrFPLoadStore {
            if isLoad {
                registerUse.write(rt(instruction))
            } else {
                registerUse.read(rt(instruction))
            }
        }
        return true
    }

    if instruction & 0x3B000000 == 0x39000000 {
        let isLoad = (instruction & 0x00400000) != 0
        let isSIMDOrFPLoadStore = (instruction & 0x04000000) != 0

        registerUse.read(rn(instruction))
        if !isSIMDOrFPLoadStore {
            if isLoad {
                registerUse.write(rt(instruction))
            } else {
                registerUse.read(rt(instruction))
            }
        }
        return true
    }

    if instruction & 0x3B200C00 == 0x38000800 {
        let isLoad = (instruction & 0x00400000) != 0
        let isSIMDOrFPLoadStore = (instruction & 0x04000000) != 0
        let addressing = (instruction >> 10) & 0x3
        let isWriteback = addressing == 0b01 || addressing == 0b11

        registerUse.read(rn(instruction))
        if !isSIMDOrFPLoadStore {
            if isLoad {
                registerUse.write(rt(instruction))
            } else {
                registerUse.read(rt(instruction))
            }
        }

        if isWriteback {
            registerUse.write(rn(instruction))
        }
        return true
    }

    return false
}

private func decodeDataProcessingImmediate(_ instruction: UInt32, into registerUse: inout RegisterUse) -> Bool {
    if instruction & 0x9F000000 == 0x10000000 || instruction & 0x9F000000 == 0x90000000 {
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x7F800000 == 0x12800000 || instruction & 0x7F800000 == 0x52800000 {
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x7F800000 == 0x72800000 {
        registerUse.read(rd(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x7F000000 == 0x11000000 ||
        instruction & 0x7F000000 == 0x31000000 ||
        instruction & 0x7F000000 == 0x51000000 ||
        instruction & 0x7F000000 == 0x71000000 {
        registerUse.read(rn(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x7F800000 == 0x12000000 ||
        instruction & 0x7F800000 == 0x32000000 ||
        instruction & 0x7F800000 == 0x52000000 ||
        instruction & 0x7F800000 == 0x72000000 {
        registerUse.read(rn(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x7F000000 == 0x34000000 || instruction & 0x7F000000 == 0x35000000 {
        registerUse.read(rt(instruction))
        return true
    }

    if instruction & 0x7F800000 == 0x13000000 ||
        instruction & 0x7F800000 == 0x33000000 ||
        instruction & 0x7F800000 == 0x53000000 {
        registerUse.read(rn(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x7FA00000 == 0x13800000 {
        registerUse.read(rn(instruction))
        registerUse.read(rm(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    return false
}

private func decodeDataProcessingRegister(_ instruction: UInt32, into registerUse: inout RegisterUse) -> Bool {
    if instruction & 0x1F000000 == 0x0A000000 {
        registerUse.read(rn(instruction))
        registerUse.read(rm(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x1F200000 == 0x0B000000 {
        registerUse.read(rn(instruction))
        registerUse.read(rm(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x1FE00000 == 0x1A800000 {
        registerUse.read(rn(instruction))
        registerUse.read(rm(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x1F000000 == 0x1B000000 {
        registerUse.read(rn(instruction))
        registerUse.read(rm(instruction))
        registerUse.read(ra(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x5FE00000 == 0x5AC00000 {
        registerUse.read(rn(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0x5FE00000 == 0x5A000000 {
        registerUse.read(rn(instruction))
        registerUse.read(rm(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    return false
}

private func decodeBranchesAndSystem(_ instruction: UInt32, into registerUse: inout RegisterUse) -> Bool {
    if instruction & 0x7E000000 == 0x36000000 {
        registerUse.read(rt(instruction))
        return true
    }

    if instruction & 0x7E000000 == 0x6A000000 {
        registerUse.read(rn(instruction))
        registerUse.read(rm(instruction))
        registerUse.write(rd(instruction))
        return true
    }

    if instruction & 0xFFFFFC1F == 0xD61F0000 ||
        instruction & 0xFFFFFC1F == 0xD63F0000 ||
        instruction & 0xFFFFFC1F == 0xD65F0000 {
        registerUse.read((instruction >> 5) & 0x1F)
        return true
    }

    if instruction & 0xFFF00000 == 0xD5300000 {
        registerUse.write(rt(instruction))
        return true
    }

    if instruction & 0xFFF00000 == 0xD5100000 {
        registerUse.read(rt(instruction))
        return true
    }

    return false
}

private func addConservativeRegisterFields(_ instruction: UInt32, into registerUse: inout RegisterUse) {
    let fields = [rd(instruction), rn(instruction), rm(instruction), ra(instruction), rt2(instruction)]

    for field in fields where field != 31 {
        registerUse.read(field)
        registerUse.write(field)
    }
}

private func rd(_ instruction: UInt32) -> UInt32 {
    instruction & 0x1F
}

private func rt(_ instruction: UInt32) -> UInt32 {
    instruction & 0x1F
}

private func rn(_ instruction: UInt32) -> UInt32 {
    (instruction >> 5) & 0x1F
}

private func rm(_ instruction: UInt32) -> UInt32 {
    (instruction >> 16) & 0x1F
}

private func rs(_ instruction: UInt32) -> UInt32 {
    (instruction >> 16) & 0x1F
}

private func ra(_ instruction: UInt32) -> UInt32 {
    (instruction >> 10) & 0x1F
}

private func rt2(_ instruction: UInt32) -> UInt32 {
    (instruction >> 10) & 0x1F
}
