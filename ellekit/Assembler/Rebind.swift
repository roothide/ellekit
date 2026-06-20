
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

func combine(_ isns: [UInt8]) -> UInt32 {
    let instruction: UInt64 = (UInt64(isns[3]) | UInt64(isns[2]) << 8 | UInt64(isns[1]) << 16 | UInt64(isns[0]) << 24)
    return UInt32(instruction)
}

typealias Instructions = [[UInt8]]

extension FlattenSequence {
    func literal() -> [Self.Element] {
        Array(self)
    }
}

func signExtend(_ immediate: UInt32, _ offset: UInt8) -> Int32 {
    var result = Int32(bitPattern: immediate)
    let signBit = (immediate >> offset) & 0x1
    for i in (offset + 1) ..< 32 {
        result |= Int32(bitPattern: signBit << i)
    }
    return result
}

private func addSignedOffset(_ base: UInt64, _ offset: Int64) -> UInt64 {
    base &+ UInt64(bitPattern: offset)
}

private enum RebindTarget {
    case absolute(UInt64)
    case copiedInstruction(Int)
}

private enum RebindOperation {
    case raw([UInt8])
    case adr(target: UInt64, register: Int)
    case adrp(target: UInt64, register: Int)
    case conditionalBranch(cond: UInt32, target: RebindTarget)
    case cbz(register: Int, is64Bit: Bool, target: RebindTarget)
    case cbnz(register: Int, is64Bit: Bool, target: RebindTarget)
    case tbzTbnz(op: UInt32, bit: Int, register: Register, target: RebindTarget)
    case integerLiteralLoad(opc: UInt32, rt: Int, addr: UInt64)
    case fpLiteralLoad(opc: UInt32, rt: Int, addr: UInt64)
    case branch(link: Bool, target: RebindTarget)

    var size: Int {
        switch self {
        case .raw(let bytes):
            return bytes.count
        case .adr, .adrp:
            return 16
        case .conditionalBranch, .cbz, .cbnz, .tbzTbnz:
            return 28
        case .integerLiteralLoad(let opc, let rt, _):
            return rt == 31 || opc == 0b11 ? 4 : 20
        case .fpLiteralLoad(let opc, _, _):
            return opc == 0b11 ? 4 : 20
        case .branch:
            return 20
        }
    }
}

extension Instructions {
    func rebind(formerPC: UInt64, newPC: UInt64, tmpReg: Register) -> [UInt8] {
        let operations = self.enumerated().map { pair in
            parseRebindOperation(
                pair.element,
                index: pair.offset,
                formerPC: formerPC,
                copiedInstructionCount: self.count
            )
        }
        
        var relocatedOffset = 0
        // original instruction index -> relocated PC
        var relocatedMap = [UInt64](repeating: newPC, count: operations.count)

        for index in operations.indices {
            relocatedMap[index] = newPC &+ UInt64(relocatedOffset)
            relocatedOffset += operations[index].size
        }

        func resolve(_ target: RebindTarget) -> UInt64 {
            switch target {
            case .absolute(let addr):
                return addr
            case .copiedInstruction(let index):
                return relocatedMap[index]
            }
        }

        return operations.enumerated().flatMap { pair in
            emitRebindOperation(
                pair.element,
                relocatedPC: relocatedMap[pair.offset],
                tmpReg: tmpReg,
                resolve: resolve
            )
        }
    }
}

private func copiedBranchTarget(
    _ target: UInt64,
    formerPC: UInt64,
    copiedInstructionCount: Int
) -> RebindTarget {
    guard target >= formerPC else {
        return .absolute(target)
    }

    let offset = target &- formerPC
    let copiedSize = UInt64(copiedInstructionCount) * 4

    guard offset < copiedSize, offset % 4 == 0 else {
        return .absolute(target)
    }

    return .copiedInstruction(Int(offset / 4))
}

private func parseRebindOperation(
    _ byteArray: [UInt8],
    index: Int,
    formerPC: UInt64,
    copiedInstructionCount: Int
) -> RebindOperation {
    let originalPC = formerPC &+ UInt64(4 * index)
    let instruction = combine(byteArray)

    if instruction == 0x7F2303D5 { // pacibsp
        return .raw(byteArray)
    }

    let reversed = instruction.reverse()

    // MARK: - adr(p)

    if reversed & 0x9F000000 == 0x10000000 { // adr
        let target = adr.destination(reversed, originalPC)
        let register = Int(reversed.bits(0...4))
        return .adr(target: target, register: register)
    }

    if reversed & 0x9F000000 == 0x90000000 { // adrp
        let register = Int(reversed.bits(0...4))
        let target = adrp.destination(reversed, originalPC)
        return .adrp(target: target, register: register)
    }

    // MARK: - b.cond

    if reversed >> 25 == b.condBase >> 25 {
        let cond = reversed & 0xf
        let target = addSignedOffset(originalPC, Int64(signExtend(((reversed >> 5) & 0x7ffff), 18)) * 4)
        return .conditionalBranch(
            cond: cond,
            target: copiedBranchTarget(target, formerPC: formerPC, copiedInstructionCount: copiedInstructionCount)
        )
    }

    // MARK: - 64-bit CBZ/CBNZ

    if reversed >> 24 == (cbz.base | (1 << 31)) >> 24 {
        let register = Int(reversed & 0x1f)
        let target = addSignedOffset(originalPC, Int64(signExtend(((reversed >> 5) & 0x7ffff), 18)) * 4)
        return .cbz(
            register: register,
            is64Bit: true,
            target: copiedBranchTarget(target, formerPC: formerPC, copiedInstructionCount: copiedInstructionCount)
        )
    }

    if reversed >> 24 == (cbnz.base | (1 << 31)) >> 24 {
        let register = Int(reversed & 0x1f)
        let target = addSignedOffset(originalPC, Int64(signExtend(((reversed >> 5) & 0x7ffff), 18)) * 4)
        return .cbnz(
            register: register,
            is64Bit: true,
            target: copiedBranchTarget(target, formerPC: formerPC, copiedInstructionCount: copiedInstructionCount)
        )
    }

    // MARK: - 32-bit CBZ/CBNZ

    if reversed >> 24 == (cbz.base) >> 24 {
        let register = Int(reversed & 0x1f)
        let target = addSignedOffset(originalPC, Int64(signExtend(((reversed >> 5) & 0x7ffff), 18)) * 4)
        return .cbz(
            register: register,
            is64Bit: false,
            target: copiedBranchTarget(target, formerPC: formerPC, copiedInstructionCount: copiedInstructionCount)
        )
    }

    if reversed >> 24 == (cbnz.base) >> 24 {
        let register = Int(reversed & 0x1f)
        let target = addSignedOffset(originalPC, Int64(signExtend(((reversed >> 5) & 0x7ffff), 18)) * 4)
        return .cbnz(
            register: register,
            is64Bit: false,
            target: copiedBranchTarget(target, formerPC: formerPC, copiedInstructionCount: copiedInstructionCount)
        )
    }

    // MARK: - TBZ/TBNZ

    if ((reversed >> 25) & 0x3f) == 0b011011 {
        let op = (reversed >> 24) & 1                                            // 0 = TBZ, 1 = TBNZ
        let bit = Int((((reversed >> 31) & 1) << 5) | ((reversed >> 19) & 0x1f))  // b5:b40
        let rt = Register.x(Int(reversed & 0x1f))
        let target = addSignedOffset(originalPC, Int64(signExtend((reversed >> 5) & 0x3fff, 13)) * 4)
        return .tbzTbnz(
            op: op,
            bit: bit,
            register: rt,
            target: copiedBranchTarget(target, formerPC: formerPC, copiedInstructionCount: copiedInstructionCount)
        )
    }

    // MARK: - LDR/LDRSW/PRFM (literal)

    if ((reversed >> 24) & 0x3f) == 0b011000 {        // integer literal load (V = 0)
        let opc = (reversed >> 30) & 0x3
        let rt = Int(reversed & 0x1f)
        let offset = Int64(signExtend((reversed >> 5) & 0x7ffff, 18)) * 4
        let addr = addSignedOffset(originalPC, offset)
        return .integerLiteralLoad(opc: opc, rt: rt, addr: addr)
    }

    if ((reversed >> 24) & 0x3f) == 0b011100 {        // SIMD&FP literal load (V = 1)
        let opc = (reversed >> 30) & 0x3
        let rt = Int(reversed & 0x1f)
        let offset = Int64(signExtend((reversed >> 5) & 0x7ffff, 18)) * 4
        let addr = addSignedOffset(originalPC, offset)
        return .fpLiteralLoad(opc: opc, rt: rt, addr: addr)
    }

    // MARK: - Plain branches

    // B imm: bits[31:26] == 000101; BL imm: bits[31:26] == 100101
    if reversed >> 26 == b.base >> 26 || reversed >> 26 == bl.base >> 26 {
        let target = addSignedOffset(originalPC, Int64(disassembleBranchImm(UInt64(reversed))))
        return .branch(
            link: reversed & 0x80000000 == 0x80000000,
            target: copiedBranchTarget(target, formerPC: formerPC, copiedInstructionCount: copiedInstructionCount)
        )
    }

    return .raw(byteArray)
}

private func emitRebindOperation(
    _ operation: RebindOperation,
    relocatedPC: UInt64,
    tmpReg: Register,
    resolve: (RebindTarget) -> UInt64
) -> [UInt8] {
    switch operation {
    case .raw(let bytes):
        return bytes

    case .adr(let target, let register):
        print("rebinded adr")
        return assembleReference(target: target, register: register)

    case .adrp(let target, let register):
        print("rebinded adrp")
        return assembleReference(target: target, register: register)

    case .conditionalBranch(let cond, let target):
        print("rebinded b.cond")
        let jump = assembleJump(resolve(target), pc: relocatedPC, link: false, big: true, jmpReg: tmpReg)
        return b(8, cond: .init(Int(cond))).bytes() +
            b(jump.count + 4).bytes() +
            jump

    case .cbz(let register, let is64Bit, let target):
        print(is64Bit ? "rebinded cbz" : "rebinded 32-bit cbz")
        let jump = assembleJump(resolve(target), pc: relocatedPC, link: false, big: true, jmpReg: tmpReg)
        let rt = is64Bit ? Register.x(register) : Register.w(register)
        return cbz(rt, 8).bytes() +
            b(jump.count + 4).bytes() +
            jump

    case .cbnz(let register, let is64Bit, let target):
        print(is64Bit ? "rebinded cbnz" : "rebinded 32-bit cbnz")
        let jump = assembleJump(resolve(target), pc: relocatedPC, link: false, big: true, jmpReg: tmpReg)
        let rt = is64Bit ? Register.x(register) : Register.w(register)
        return cbnz(rt, 8).bytes() +
            b(jump.count + 4).bytes() +
            jump

    case .tbzTbnz(let op, let bit, let register, let target):
        print("rebinded tbz/tbnz")
        let jump = assembleJump(resolve(target), pc: relocatedPC, link: false, big: true, jmpReg: tmpReg)
        let test = op == 0 ? tbz(register, bit, 8).bytes() : tbnz(register, bit, 8).bytes()
        return test +
            b(jump.count + 4).bytes() +
            jump

    case .integerLiteralLoad(let opc, let rt, let addr):
        print("rebinded ldr literal")

        // ldr/ldrsw zr, label: result is discarded and the literal is always mapped,
        // so it has no architectural effect. rt==31 would otherwise movk into xzr
        // (dropping the address) and use .x(31)=sp as the base ([sp]); emit nop instead.
        if rt == 31 {
            return nop().bytes()
        }

        switch opc {
        case 0b00: // LDR Wt, label
            return assembleReference(target: addr, register: rt) + ldr(.w(rt), .x(rt), 0).bytes()
        case 0b01: // LDR Xt, label
            return assembleReference(target: addr, register: rt) + ldr(.x(rt), .x(rt), 0).bytes()
        case 0b10: // LDRSW Xt, label
            return assembleReference(target: addr, register: rt) + ldrsw(.x(rt), .x(rt), 0).bytes()
        default:   // 0b11 = PRFM (prefetch hint) — safe to drop
            return nop().bytes()
        }

    case .fpLiteralLoad(let opc, let rt, let addr):
        print("rebinded fp ldr literal")

        let fpBase: Int
        switch opc {
        case 0b00: fpBase = 0xBD400000     // LDR St, [xTemp]
        case 0b01: fpBase = 0xFD400000     // LDR Dt, [xTemp]
        case 0b10: fpBase = 0x3DC00000     // LDR Qt, [xTemp]
        default:   return nop().bytes()    // 0b11 reserved
        }

        let load = fpBase | (tmpReg.value << 5) | rt   // ldr Vt, [xTmp]
        let fpLoad: [UInt8] = [UInt8(load & 0xff), UInt8((load >> 8) & 0xff),
                               UInt8((load >> 16) & 0xff), UInt8((load >> 24) & 0xff)]
        return assembleReference(target: addr, register: tmpReg.value) + fpLoad

    case .branch(let link, let target):
        print("Rebinding branch")
        let reboundTarget = resolve(target)
        print(["it's jumping now to : ", String(format: "0x%02llX", reboundTarget)])
        return assembleJump(reboundTarget, pc: relocatedPC, link: link, big: true, jmpReg: tmpReg)
    }
}
