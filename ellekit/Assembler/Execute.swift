
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation
import Darwin

#if SWIFT_PACKAGE
import ellekitc
#endif

func byteArray<T: FixedWidthInteger>(from value: T) -> [UInt8] {
    Array(withUnsafeBytes(of: value.bigEndian, Array.init).dropFirst(4))
}

func dumpInstructions(_ array: [Instruction]) {
    array.forEach {
        print([
            type(of: $0),
            $0.bytes().map { "0x" + String(format: "%02X", $0) }.joined(separator: ", "),
            $0.bytes().map { String(format: "%02X", $0) }.joined()
        ])
    }
}

@resultBuilder
public struct InstructionBuilder {
    static public func buildEither(first component: Instruction) -> Instruction {
        component
    }

    static public func buildEither(second component: Instruction) -> Instruction {
        component
    }

    static public func buildBlock(_ components: Instruction...) -> [UInt8] {
        return Array(
            components.map { $0.bytes() }.joined()
        )
    }
}
