
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

public protocol Instruction {

    init(encoded: Int)

    func bytes() -> [UInt8]

}

func ror(_ x: Int, _ y: Int) -> Int {
    ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF
}

extension Instruction {
    static func encodeRegisterInt(_ base: Int, _ rd: Register, _ value: Int) -> Int {
        var base = base
        base |= (rd.w ? 0 : 1) << 31
        base |= value << 5
        base |= rd.value
        let result = reverse(base)
        return result
    }

    static func encodeRegRegRegCond(_ base: Int, _ rd: Register, _ rm: Register, _ rn: Register, _ cond: Int) -> Int {
        var base = base
        base |= (rd.w ? 0 : 1) << 31
        base |= rn.value << 16
        base |= cond << 12
        base |= rm.value << 5
        base |= rd.value
        let result = reverse(base)
        return result
    }
}

public class ret: Instruction {
    required public init(encoded: Int) {
        fatalError()
    }

    public init() {}

    public func bytes() -> [UInt8] {
        self.ret
    }

    let ret: [UInt8] = [0xc0, 0x03, 0x5f, 0xd6]
}

public class movz: Instruction {
    let value: Int

    public init(_ rd: Register, _ value: Int) {
        self.value = Self.encodeRegisterInt(Self.base, rd, value)
    }

    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: self.value)
    }

    static let base = 0b0_10_100101_00_0000000000000000_00000
}

public class movk: Instruction {
    let value: Int

    public init(_ rd: Register, _ value: Int, lsl: Int = 0) {
        var base = Self.base
        base |= (rd.w ? 0 : 1) << 31
        base |= (lsl / 16) << 21
        base |= value << 5
        base |= rd.value
        base = reverse(base)
        self.value = base
    }

    public init(_ rd: Register, _ value: UInt64, lsl: Int = 0) {
        var base = Self.base
        base |= (rd.w ? 0 : 1) << 31
        base |= (lsl / 16) << 21
        base |= Int(value) << 5
        base |= rd.value
        base = reverse(base)
        self.value = base
    }

    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: self.value)
    }

    static let base = 0b0_11_100101_00_0000000000000000_00000
}

public class csel: Instruction {
    let value: Int

    public init(_ rd: Register, _ rm: Register, _ rn: Register, _ value: Cond) {
        self.value = Self.encodeRegRegRegCond(Self.base, rd, rm, rn, value.rawValue)
    }

    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: self.value)
    }

    static let base = 0b0_0_0_11010100_00000_0000_0_0_00000_00000
}

public class bytes: Instruction {
    public let byteValues: [UInt8]

    required public init(encoded: Int) {
        self.byteValues = byteArray(from: encoded)
    }

    public init(_ bytes: UInt8...) {
        self.byteValues = bytes
    }

    public init(_ bytes: [UInt8]) {
        self.byteValues = bytes
    }

    public func bytes() -> [UInt8] {
        self.byteValues
    }
}

public class svc: Instruction {
    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: value)
    }

    let value: Int

    public init(_ sv: Int) {
        self.value = reverse(0xD4000001 | ((sv & 0xffff) << 5))
    }
}

public class str: Instruction {
    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: value)
    }

    let value: Int

    public init(_ rd: Register, _ dest: Register, _ offset: Int = 0) {
        let size = rd.w ? 0b10 : 0b11
        let scale = rd.w ? 4 : 8
        var base = Self.base
        base |= size << 30
        base |= ((offset / scale) & 0xfff) << 10
        base |= dest.value << 5
        base |= rd.value
        self.value = reverse(base)
    }

    static let base = 0b00_111_0_01_00_000000000000_00000_00000
}

// Encodes LDR (immediate, unsigned offset). `offset` is a byte offset; imm12 is scaled by the access size.
// FIX: this class previously emitted LDUR (wrong imm field layout) and lacked masking; it now
// encodes a real LDR. Use `ldur` below if you need the unscaled/signed form.
public class ldr: Instruction {
    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: value)
    }

    let value: Int

    public init(_ rt: Register, _ rn: Register, _ offset: Int = 0) {
        let size = rt.w ? 0b10 : 0b11
        let scale = rt.w ? 4 : 8
        var base = Self.base
        base |= size << 30
        base |= ((offset / scale) & 0xfff) << 10
        base |= rn.value << 5
        base |= rt.value
        self.value = reverse(base)
    }

    static let base = 0b00_111_0_01_01_000000000000_00000_00000
}

// Encodes LDUR (load register, unscaled SIGNED 9-bit immediate offset, -256...255).
public class ldur: Instruction {
    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: value)
    }

    let value: Int

    public init(_ rt: Register, _ rn: Register, _ offset: Int = 0) {
        let size = rt.w ? 0b10 : 0b11
        var base = Self.base
        base |= size << 30
        base |= (offset & 0x1ff) << 12     // imm9 (signed, 9 bits)
        base |= rn.value << 5
        base |= rt.value
        self.value = reverse(base)
    }

    static let base = 0b00_111_0_00_01_0_000000000_00_00000_00000
}

// Encodes LDRSW (immediate, unsigned offset): loads 32 bits and sign-extends into a 64-bit register.
public class ldrsw: Instruction {
    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: value)
    }

    let value: Int

    public init(_ rt: Register, _ rn: Register, _ offset: Int = 0) {
        var base = Self.base
        base |= ((offset / 4) & 0xfff) << 10
        base |= rn.value << 5
        base |= rt.value
        self.value = reverse(base)
    }

    static let base = 0b10_111_0_01_10_000000000000_00000_00000
}

// Encodes TBZ (test bit and branch if zero). `bit` is the bit number (0...63); `offset` is a byte offset.
public class tbz: Instruction {
    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: value)
    }

    let value: Int

    public init(_ rt: Register, _ bit: Int, _ offset: Int) {
        var base = Self.base
        base |= ((bit >> 5) & 0x1) << 31           // b5
        base |= (bit & 0x1f) << 19                 // b40
        base |= ((offset / 4) & 0x3fff) << 5       // imm14
        base |= rt.value
        self.value = reverse(base)
    }

    static let base = 0b0_011011_0_00000_00000000000000_00000
}

// Encodes TBNZ (test bit and branch if nonzero). `bit` is the bit number (0...63); `offset` is a byte offset.
public class tbnz: Instruction {
    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: value)
    }

    let value: Int

    public init(_ rt: Register, _ bit: Int, _ offset: Int) {
        var base = Self.base
        base |= ((bit >> 5) & 0x1) << 31           // b5
        base |= (bit & 0x1f) << 19                 // b40
        base |= ((offset / 4) & 0x3fff) << 5       // imm14
        base |= rt.value
        self.value = reverse(base)
    }

    static let base = 0b0_011011_1_00000_00000000000000_00000
}

public class nop: Instruction {

    required public init(encoded: Int) {
    }

    public init() {}

    let value = 0x1F2003D5

    public func bytes() -> [UInt8] {
        byteArray(from: self.value)
    }
}

class adrp: Instruction {
    required public init(encoded: Int) {
        self.value = encoded
    }

    public func bytes() -> [UInt8] {
        byteArray(from: value)
    }

    let value: Int

    public init(_ rt: Register, _ label: Int = 0) {
        var base = Self.base
        let imm = (label >> 12)
        let immlow = ((imm & 0x3) << 29)
        let immhigh = ((imm >> 2) & 0x7ffff) << 5
        base |= immlow
        base |= immhigh
        base |= rt.value
        self.value = reverse(base)
    }

    static let base = 0b1_00_10000_0000000000000000000_00000

    static func destination(_ instruction: UInt32, _ pc: UInt64) -> UInt64 {
        // Calculate imm from hi and lo
        var imm_hi_lo = UInt64((instruction >> 3)  & 0x1FFFFC)
        imm_hi_lo    |= UInt64((instruction >> 29) & 0x3)
        if (instruction & 0x800000) != 0 {
            // Sign extend
            imm_hi_lo |= 0xFFFFFFFFFFE00000
        }

        // Build real imm
        let imm = (imm_hi_lo << 12)
        
        // Emulate
        return (pc & ~0xFFF) &+ UInt64(imm)
    }

}

public class adr: Instruction {
    required public init(encoded: Int) {
        self.value = encoded
        self.register = Register.x(encoded.reverse().bits(0...4))
        self.label = Int(Self.destination(UInt32(encoded.reverse()), 0))
    }

    public func bytes() -> [UInt8] {
        byteArray(from: value)
    }

    public var _cyanideTarget: Int? = nil
    
    public init(_ rt: Register, data: Int = 0) {
        self.register = rt
        self._cyanideTarget = data
        self.label = 0
        self.value = -1
    }
    
    public let value: Int
    public let register: Register
    public let label: Int

    public init(_ rt: Register, _ label: Int = 0) {
        self.register = rt
        self.label = label
        var base = Self.base
        let immlow = label & 0x3
        let immhigh = label >> 2 & 0x7ffff
        base |= immlow << 29
        base |= immhigh << 5
        base |= rt.value
        self.value = reverse(base)
    }

    public convenience init?(isn: UInt32, formerPC: UInt64, newPC: UInt64) {
        let target = Self.destination(isn, formerPC)
        let rt = isn.bits(0...4)
        self.init(.x(Int(rt)), Int(target - newPC))
    }

    static let base = 0b0_00_10000_0000000000000000000_00000

    static public func destination(_ instruction: UInt32, _ pc: UInt64) -> UInt64 {

        var imm_hi_lo = UInt64((instruction >> 3)  & 0x1FFFFC)
        imm_hi_lo    |= UInt64((instruction >> 29) & 0x3)
        if (instruction & 0x800000) != 0 {
            // Sign extend
            imm_hi_lo |= 0xFFFFFFFFFFE00000
        }
        
        return pc &+ UInt64(imm_hi_lo)
    }
}
