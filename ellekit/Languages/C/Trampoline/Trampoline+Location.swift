
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation
import MachO

extension Trampoline {

    /// Find a borrowable "victim" function to host the 32-byte trampoline.
    ///
    /// Strategy: read the image's `LC_FUNCTION_STARTS` table (exact, metadata-backed
    /// function entries — no mid-function "cold block" false positives, and it includes
    /// exported / pointer-called functions), then walk it in table order and pick the
    /// first suitable function. This is intentionally not a closest-victim search:
    /// ranking candidates would either need extra state or extra `getSafeRebindSize`
    /// probes on multiple victims. The chosen victim must be (a) within ±128MB — the
    /// reach of the single `b` the hook uses — and (b) long enough (> 8 instructions)
    /// to relocate its prologue and jump back.
    func findVictimFunction(size : Int) -> (UnsafeMutableRawPointer, Int)? {

        let baseAddr = UInt(bitPattern: self.base)
        let replacementAddr = UInt(bitPattern: self.target)

        let starts = functionStarts(containing: self.base)
        guard starts.count >= 2 else {
            print("[-] trampoline: no LC_FUNCTION_STARTS for this image base=\(self.base) target=\(self.target) startsCount=\(starts.count)")
            return nil
        }

        // hook() patches base with a single `b` to the trampoline's replacement slot (offset 16), so
        // that branch must fit an arm64 `b`'s range [-0x800_0000, +0x7FF_FFFC] — there is no fallback,
        // an out-of-range offset would just be silently truncated to a wrong target. Rather than
        // hardcode the slot's +16 offset, reserve a conservative margin of size*4 bytes (the whole
        // borrowed span, always >= 16) at both ends of the range. The margin must shrink both ends,
        // not shift the offset point, so a victim sitting just inside the raw reach is still excluded.
        let margin = size * 4

        // starts[] is ascending; the size of function i is starts[i+1] - starts[i].
        // Return the first suitable victim in this order, not the closest one.
        var skippedBase = 0
        var skippedReplacement = 0
        var skippedRange = 0
        var skippedSmall = 0
        var skippedRebind = 0
        for i in 0 ..< (starts.count - 1) {
            let s = starts[i]
            let next = starts[i + 1]
            if baseAddr >= s && baseAddr < next {
                skippedBase += 1
                continue
            }   // victim must not be / contain base
            if replacementAddr >= s && replacementAddr < next {
                skippedReplacement += 1
                continue
            } // victim must not be / contain replacement

            let offset = Int(bitPattern: s &- baseAddr)        // signed distance from base to victim entry
            if offset < -0x800_0000 + margin || offset > 0x7FF_FFFC - margin {
                skippedRange += 1
                continue
            }  // reachable by a single `b`

            let span = next - s                                // bytes (code + any trailing padding)
            if span < 9 * 4 {
                skippedSmall += 1
                continue
            }                       // need > 8 instructions of room

            guard let ptr = UnsafeMutableRawPointer(bitPattern: s) else { continue }
            // confirm the first instructions are real code we can relocate
            // (guards against function-starts spans that are mostly trailing padding)
            let rebindSize = getSafeRebindSize(ptr, desiredSize: size)
            if rebindSize < size {
                skippedRebind += 1
                print("[-] trampoline: victim rejected by rebindSize base=\(self.base) target=\(self.target) candidate=\(ptr) requestedSize=\(size) rebindSize=\(rebindSize) span=\(span) offset=\(offset)")
                continue
            }

            print("[+] trampoline: victim @ \(ptr) base=\(self.base) target=\(self.target) size=\(rebindSize) span=\(span) offset=\(offset)")
            return (ptr, rebindSize)
        }

        print("[-] trampoline: no suitable victim within ±128MB base=\(self.base) target=\(self.target) startsCount=\(starts.count) skippedBase=\(skippedBase) skippedReplacement=\(skippedReplacement) skippedRange=\(skippedRange) skippedSmall=\(skippedSmall) skippedRebind=\(skippedRebind)")
        return nil
    }

    /// Find unused zero-filled padding between the Mach-O load commands and the first __TEXT
    /// section. This is used as the preferred trampoline storage before borrowing a victim function.
    func findHeaderStub(near target: UnsafeMutableRawPointer, size: Int) -> UnsafeMutableRawPointer? {
        guard size > 0 else {
            print("[-] trampoline: header search invalid size target=\(target) size=\(size)")
            return nil
        }

        guard let range = headerPaddingRange(containing: target) else {
            print("[-] trampoline: no header padding range target=\(target) size=\(size)")
            return nil
        }

        let targetAddr = UInt(bitPattern: target)
        let alignment = UInt(8)
        let alignmentMask = alignment - 1
        var candidate = (range.lowerBound + alignmentMask) & ~alignmentMask
        var checked = 0
        var rejectedRange = 0
        var rejectedAlignment = 0
        var rejectedNonZero = 0

        while candidate < range.upperBound {
            guard range.upperBound - candidate >= UInt(size) else { break }
            checked += 1

            let offset = Int(bitPattern: candidate &- targetAddr)
            guard offset >= -0x800_0000 && offset <= 0x7FF_FFFC else {
                rejectedRange += 1
                candidate += alignment
                continue
            }
            guard offset % 4 == 0 else {
                rejectedAlignment += 1
                candidate += alignment
                continue
            }
            if let rawPtr = UnsafeRawPointer(bitPattern: candidate),
               let ptr = UnsafeMutableRawPointer(bitPattern: candidate) {
                var isZero = true
                for byteOffset in 0 ..< size {
                    if rawPtr.load(fromByteOffset: byteOffset, as: UInt8.self) != 0 {
                        isZero = false
                        break
                    }
                }
                if isZero {
                    print("[*] trampoline: header padding candidate target=\(target) ptr=\(ptr) size=\(size) offset=\(offset) checked=\(checked)")
                    return ptr
                }
                rejectedNonZero += 1
            }

            candidate += alignment
        }

        print("[-] trampoline: no header padding slot target=\(target) size=\(size) range=0x\(String(range.lowerBound, radix: 16))..0x\(String(range.upperBound, radix: 16)) checked=\(checked) rejectedRange=\(rejectedRange) rejectedAlignment=\(rejectedAlignment) rejectedNonZero=\(rejectedNonZero)")
        return nil
    }
}

/// Returns the runtime padding range between the Mach-O load commands and the
/// first __TEXT section. Only this header tail is considered safe for stubs.
private func headerPaddingRange(containing target: UnsafeMutableRawPointer) -> Range<UInt>? {
    var info = Dl_info()
    guard dladdr(target, &info) != 0, let headerRaw = info.dli_fbase else { return nil }

    let header = headerRaw.assumingMemoryBound(to: mach_header_64.self)
    let mh = header.pointee
    guard mh.magic == MH_MAGIC_64 else { return nil }

    let imageBase = UInt(bitPattern: headerRaw)
    let lcStart = UnsafeRawPointer(header).advanced(by: MemoryLayout<mach_header_64>.size)
    let lcEnd = lcStart.advanced(by: Int(mh.sizeofcmds))
    let loadCommandsEnd = UInt(bitPattern: lcEnd)

    var firstTextSectionStart: UInt?
    var cmd = lcStart

    for _ in 0 ..< Int(mh.ncmds) {
        if cmd.advanced(by: MemoryLayout<load_command>.size) > lcEnd { return nil }
        let lc = cmd.assumingMemoryBound(to: load_command.self).pointee
        if lc.cmdsize < UInt32(MemoryLayout<load_command>.size) { return nil }

        let commandEnd = cmd.advanced(by: Int(lc.cmdsize))
        if commandEnd > lcEnd { return nil }

        if lc.cmd == UInt32(LC_SEGMENT_64) {
            guard lc.cmdsize >= UInt32(MemoryLayout<segment_command_64>.size) else { return nil }

            var seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
            let name = withUnsafeBytes(of: &seg.segname) { raw -> String in
                String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
            }

            if name == "__TEXT" {
                let sectionStart = cmd.advanced(by: MemoryLayout<segment_command_64>.size)
                let sectionBytes = Int(seg.nsects) * MemoryLayout<section_64>.stride
                guard sectionStart.advanced(by: sectionBytes) <= commandEnd else { return nil }

                let slide = imageBase &- UInt(seg.vmaddr)
                for index in 0 ..< Int(seg.nsects) {
                    let section = sectionStart
                        .advanced(by: index * MemoryLayout<section_64>.stride)
                        .assumingMemoryBound(to: section_64.self)
                        .pointee
                    let sectionStartAddr = UInt(section.addr) &+ slide
                    guard sectionStartAddr > loadCommandsEnd else { continue }
                    firstTextSectionStart = min(firstTextSectionStart ?? sectionStartAddr, sectionStartAddr)
                }
            }
        }

        cmd = commandEnd
    }

    guard let firstTextSectionStart, firstTextSectionStart > loadCommandsEnd else {
        return nil
    }

    return loadCommandsEnd ..< firstTextSectionStart
}

/// Decode `LC_FUNCTION_STARTS` for the image containing `addr`.
/// Returns runtime function-entry addresses in ascending order, or `[]` if unavailable.
private func functionStarts(containing addr: UnsafeMutableRawPointer) -> [UInt] {

    var info = Dl_info()
    guard dladdr(addr, &info) != 0, let headerRaw = info.dli_fbase else { return [] }

    let header = headerRaw.assumingMemoryBound(to: mach_header_64.self)
    guard header.pointee.magic == MH_MAGIC_64 else { return [] }

    let imageBase = UInt(bitPattern: headerRaw)      // runtime mach_header address

    var textVmaddr: UInt64? = nil
    var textVmsize: UInt64 = 0
    var linkeditVmaddr: UInt64 = 0
    var linkeditFileoff: UInt64 = 0
    var fnDataoff: UInt32 = 0
    var fnDatasize: UInt32 = 0

    let lcStart = UnsafeRawPointer(header).advanced(by: MemoryLayout<mach_header_64>.size)
    let lcEnd = lcStart.advanced(by: Int(header.pointee.sizeofcmds))
    var cmd = lcStart
    for _ in 0 ..< Int(header.pointee.ncmds) {
        if cmd.advanced(by: MemoryLayout<load_command>.size) > lcEnd { break }   // past LC region
        let lc = cmd.assumingMemoryBound(to: load_command.self).pointee
        if lc.cmdsize < UInt32(MemoryLayout<load_command>.size) { break }        // malformed guard
        if cmd.advanced(by: Int(lc.cmdsize)) > lcEnd { break }                   // command overruns

        if lc.cmd == UInt32(LC_SEGMENT_64) {
            var seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
            let name = withUnsafeBytes(of: &seg.segname) { raw -> String in
                String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
            if name == "__TEXT" {
                textVmaddr = seg.vmaddr
                textVmsize = seg.vmsize
            } else if name == "__LINKEDIT" {
                linkeditVmaddr = seg.vmaddr
                linkeditFileoff = seg.fileoff
            }
        } else if lc.cmd == UInt32(LC_FUNCTION_STARTS) {
            let led = cmd.assumingMemoryBound(to: linkedit_data_command.self).pointee
            fnDataoff = led.dataoff
            fnDatasize = led.datasize
        }

        cmd = cmd.advanced(by: Int(lc.cmdsize))
    }

    guard let textVm = textVmaddr, linkeditVmaddr != 0, fnDatasize > 0,
          UInt64(fnDataoff) >= linkeditFileoff else { return [] }

    // Locate the blob: __LINKEDIT runtime base + its offset within __LINKEDIT.
    let slide = imageBase &- UInt(textVm)
    let dataAddr = UInt(linkeditVmaddr) &+ slide &+ (UInt(fnDataoff) &- UInt(linkeditFileoff))
    guard let dataPtr = UnsafeRawPointer(bitPattern: dataAddr) else { return [] }

    // ULEB128 deltas, accumulated from the image base.
    let textEnd = imageBase &+ UInt(textVmsize)        // valid range for any function entry
    var result: [UInt] = []
    var p = dataPtr
    let end = dataPtr.advanced(by: Int(fnDatasize))
    var current = imageBase

    while p < end {
        var value: UInt = 0
        var shift: UInt = 0
        var done = false
        while p < end {
            let b = p.load(as: UInt8.self)
            p = p.advanced(by: 1)
            value |= UInt(b & 0x7f) << shift
            if (b & 0x80) == 0 { done = true; break }
            shift &+= 7
            if shift >= UInt(MemoryLayout<UInt>.size * 8) { break }    // malformed guard
        }
        if !done || value == 0 { break }            // trailing zero padding / end of table
        current &+= value
        // Defense-in-depth: a correct decode never leaves __TEXT. If it does (e.g. a
        // mis-resolved data pointer on an unexpected cache layout), bail rather than
        // hand back garbage addresses that could be picked as a victim.
        if current < imageBase || current >= textEnd { return [] }
        result.append(current)
    }

    return result
}
