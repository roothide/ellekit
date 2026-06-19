
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

func reverse<T: FixedWidthInteger>(_ base: T) -> T {
    let b0: T = (base >> 24) & 0xff
    let b1: T = (base << 8)  & 0xff0000
    let b2: T = (base >> 8)  & 0xff00
    let b3: T = (base << 24) & 0xff000000
    return b0 | b1 | b2 | b3
}

extension FixedWidthInteger {
    public func reverse() -> Self {
        let b0: Self = (self >> 24) & 0xff
        let b1: Self = (self << 8)  & 0xff0000
        let b2: Self = (self >> 8)  & 0xff00
        let b3: Self = (self << 24) & 0xff000000
        return b0 | b1 | b2 | b3
    }
}

extension FixedWidthInteger {
    func bits(_ range: ClosedRange<Self>) -> Self {
        let amount: Self = (range.upperBound - range.lowerBound) + 1
        let mask: Self = ((1 << amount) - 1) << range.lowerBound

        return (self & mask) >> range.lowerBound
    }
}

extension Array {
    func chunked(into size: Int) -> [[Element]] {
        return stride(from: 0, to: count, by: size).map {
            Array(self[$0 ..< Swift.min($0 + size, count)])
        }
    }
}
