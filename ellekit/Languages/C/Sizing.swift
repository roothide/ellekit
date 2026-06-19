// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

private struct BasicBlock {
    let startIndex: Int
    let endIndex: Int
    let successors: [Int]
    let branchEdges: [BranchEdge]

    init(
        startIndex: Int,
        endIndex: Int,
        successors: [Int],
        branchEdges: [BranchEdge] = []
    ) {
        self.startIndex = startIndex
        self.endIndex = endIndex
        self.successors = successors
        self.branchEdges = branchEdges
    }
}

private struct BasicBlocks {
    let blocks: [BasicBlock]
}

private struct ImmediateBranch {
    let targetIndex: Int
    let hasFallthrough: Bool
}

private struct BranchEdge {
    let sourceIndex: Int
    let targetIndex: Int
}

private func debugBlock(_ block: BasicBlock) -> String {
    let successors = block.successors.map(String.init).joined(separator: ",")
    let branchEdges = block.branchEdges
        .map { "\($0.sourceIndex)->\($0.targetIndex)" }
        .joined(separator: ",")
    return "{start:\(block.startIndex),end:\(block.endIndex),succ:[\(successors)],branchEdges:[\(branchEdges)]}"
}

private func debugBlocks(_ blocks: [BasicBlock]) -> String {
    return "[" + blocks.map(debugBlock).joined(separator: ", ") + "]"
}

private func debugInstructionWords(instruction: (Int) -> UInt32, count: Int) -> String {
    guard count > 0 else { return "[]" }

    let words = (0..<count).map { idx in
        String(format: "0x%08x", instruction(idx))
    }

    return "[" + words.joined(separator: ", ") + "]"
}

/*
 Returns the largest safe rebind prefix up to `desiredSize`.

 The returned size is the rebind/orig copy window. Callers may patch any prefix
 no larger than this value, but `getOriginal` must copy the full returned size.
 `target + 0` is treated as the hooked function entry; only explicit branch
 edges from outside the copied window into `[target + 4, target + size * 4)`
 make a candidate size unsafe.
 */
func getSafeRebindSize(_ target: UnsafeMutableRawPointer, desiredSize: Int) -> Int
{
    guard desiredSize > 0 else {
        return 0
    }

    func instruction(_ idx: Int) -> UInt32 {
        return target.advanced(by: idx * MemoryLayout<UInt32>.size).load(as: UInt32.self)
    }

    let linearEnd = linearPatchableEnd(desiredSize: desiredSize, instruction: instruction)
    let basicBlocks = collectBasicBlocks(instruction: instruction)
    let firstInstructions = debugInstructionWords(instruction: instruction, count: 8)
    print("[*] ellekit: getSafeRebindSize target=\(target) desiredSize=\(desiredSize) linearEnd=\(linearEnd) firstInstructions=\(firstInstructions)")

    let candidateEnd = min(desiredSize, linearEnd)
    let branchEdges = basicBlocks.blocks.flatMap { $0.branchEdges }

    for size in stride(from: candidateEnd, through: 1, by: -1) {
        let unsafeEdges = branchEdges.filter { edge in
            let sourceOutsideCopiedWindow = edge.sourceIndex < 0 || edge.sourceIndex >= size
            return sourceOutsideCopiedWindow && edge.targetIndex > 0 && edge.targetIndex < size
        }

        if unsafeEdges.isEmpty {
            if size != candidateEnd {
                let edgesDescription = branchEdges
                    .map { "\($0.sourceIndex)->\($0.targetIndex)" }
                    .joined(separator: ",")
                print("[-] ellekit: getSafeRebindSize reduced target=\(target) desiredSize=\(desiredSize) candidateEnd=\(candidateEnd) safeSize=\(size) branchEdges=[\(edgesDescription)] blocks=\(debugBlocks(basicBlocks.blocks))")
            }
            return size
        }
    }

    return 0
}

private func linearPatchableEnd(desiredSize: Int, instruction: (Int) -> UInt32) -> Int
{
    var idx = 0

    while idx < desiredSize {
        let isn = instruction(idx)

        if isNoFallthroughTerminator(isn) {
            return idx + 1
        }

        if bImmediateTargetIndex(isn, from: idx) != nil {
            return idx + 1
        }

        if let branch = conditionalImmediateBranch(isn, from: idx), !branch.hasFallthrough {
            return idx + 1
        }

        idx += 1
    }

    return desiredSize
}

private func collectBasicBlocks(instruction: (Int) -> UInt32) -> BasicBlocks
{
    var leaders = Set<Int>([0])
    var scannedLeaders = Set<Int>([0])
    var worklist = [Int]()
    let entryBlock = scanBasicBlock(from: 0, instruction: instruction)
    var rawBlocks = [entryBlock]

    func enqueueSuccessors(of block: BasicBlock) {
        for successor in block.successors {
            if leaders.insert(successor).inserted {
                worklist.append(successor)
            }
        }
    }

    enqueueSuccessors(of: entryBlock)

    while let startIndex = worklist.popLast() {
        guard !scannedLeaders.contains(startIndex) else { continue }

        scannedLeaders.insert(startIndex)

        if rawBlocks.contains(where: { $0.startIndex <= startIndex && startIndex < $0.endIndex }) {
            continue
        }

        let block = scanBasicBlock(from: startIndex, instruction: instruction)
        rawBlocks.removeAll { block.startIndex <= $0.startIndex && $0.endIndex <= block.endIndex }
        rawBlocks.append(block)

        enqueueSuccessors(of: block)
    }

    return BasicBlocks(blocks: finalizeBasicBlocks(rawBlocks, leaders: leaders))
}

private func finalizeBasicBlocks(_ rawBlocks: [BasicBlock], leaders: Set<Int>) -> [BasicBlock]
{
    var blocks = [BasicBlock]()

    for block in rawBlocks.sorted(by: { $0.startIndex < $1.startIndex }) {
        var segmentStart = block.startIndex
        let splitPoints = leaders.filter { $0 > block.startIndex && $0 < block.endIndex }.sorted()

        for splitPoint in splitPoints {
            blocks.append(BasicBlock(startIndex: segmentStart, endIndex: splitPoint, successors: [splitPoint]))
            segmentStart = splitPoint
        }

        blocks.append(BasicBlock(
            startIndex: segmentStart,
            endIndex: block.endIndex,
            successors: block.successors,
            branchEdges: block.branchEdges
        ))
    }

    return blocks
}

private func scanBasicBlock(from startIndex: Int, instruction: (Int) -> UInt32) -> BasicBlock
{
    var idx = startIndex
    var branchEdges = [BranchEdge]()

    while true {
        let isn = instruction(idx)

        if let targetIdx = blImmediateTargetIndex(isn, from: idx) {
            // BL is a call: it returns, so we keep scanning linearly and do NOT
            // add the target as a successor (it usually points into another
            // function; following it would run off into unrelated code). We
            // still record the edge so the reentry check can catch an out-of-
            // window BL that lands back inside the copied prologue.
            branchEdges.append(BranchEdge(sourceIndex: idx, targetIndex: targetIdx))
            idx += 1
            continue
        }

        if isNoFallthroughTerminator(isn) {
            return BasicBlock(startIndex: startIndex, endIndex: idx + 1, successors: [], branchEdges: branchEdges)
        }

        if let targetIdx = bImmediateTargetIndex(isn, from: idx) {
            branchEdges.append(BranchEdge(sourceIndex: idx, targetIndex: targetIdx))
            return BasicBlock(
                startIndex: startIndex,
                endIndex: idx + 1,
                successors: [targetIdx],
                branchEdges: branchEdges
            )
        }

        if let branch = conditionalImmediateBranch(isn, from: idx)
        {
            guard branch.hasFallthrough else {
                return BasicBlock(
                    startIndex: startIndex,
                    endIndex: idx + 1,
                    successors: [branch.targetIndex],
                    branchEdges: branchEdges + [BranchEdge(sourceIndex: idx, targetIndex: branch.targetIndex)]
                )
            }

            return BasicBlock(
                startIndex: startIndex,
                endIndex: idx + 1,
                successors: [branch.targetIndex, idx + 1],
                branchEdges: branchEdges + [BranchEdge(sourceIndex: idx, targetIndex: branch.targetIndex)]
            )
        }

        idx += 1
    }
}

private func bImmediateTargetIndex(_ isn: UInt32, from idx: Int) -> Int? {
    guard isn >> 26 == 0b000101 else { return nil }
    return idx + Int(signExtend(isn & 0x03ff_ffff, 25))
}

private func blImmediateTargetIndex(_ isn: UInt32, from idx: Int) -> Int? {
    guard isn >> 26 == 0b100101 else { return nil }
    return idx + Int(signExtend(isn & 0x03ff_ffff, 25))
}

private func conditionalImmediateBranch(_ isn: UInt32, from idx: Int) -> ImmediateBranch? {
    // b.cond: [31:24] = 01010100, imm19 at [23:5]
    if isn >> 24 == 0x54 {
        return ImmediateBranch(
            targetIndex: idx + Int(signExtend((isn >> 5) & 0x7ffff, 18)),
            hasFallthrough: (isn & 0xf) < 0xe
        )
    }

    // CBZ/CBNZ: [30:25] = 011010, imm19 at [23:5]
    if (isn >> 25) & 0x3f == 0b011010 {
        return ImmediateBranch(
            targetIndex: idx + Int(signExtend((isn >> 5) & 0x7ffff, 18)),
            hasFallthrough: true
        )
    }

    // TBZ/TBNZ: [30:25] = 011011, imm14 at [18:5]
    if (isn >> 25) & 0x3f == 0b011011 {
        return ImmediateBranch(
            targetIndex: idx + Int(signExtend((isn >> 5) & 0x3fff, 13)),
            hasFallthrough: true
        )
    }

    return nil
}

private func isNoFallthroughTerminator(_ isn: UInt32) -> Bool {
    // RET xN
    if (isn & 0xFFFFFC1F) == 0xD65F0000 { return true }

    // RETAA/RETAB
    if (isn & 0xFFFFFBFF) == 0xD65F0BFF { return true }

    // BR xN
    if (isn & 0xFFFFFC1F) == 0xD61F0000 { return true }

    // BRAA/BRAB xN, xM
    if (isn & 0xFFFFF800) == 0xD71F0800 { return true }

    // BRAAZ/BRABZ xN
    if (isn & 0xFFFFF81F) == 0xD61F081F { return true }

    // BRK #imm / HLT #imm
    if (isn & 0xFFE0001F) == 0xD4200000 { return true }
    if (isn & 0xFFE0001F) == 0xD4400000 { return true }

    return false
}
