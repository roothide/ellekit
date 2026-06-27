
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import ObjectiveC
import MachO

@_cdecl("MSGetImageByName")
public func MSGetImageByName(_ filename: UnsafeRawPointer) -> UnsafeRawPointer? {
    if let image = try? ellekit.openImage(image: String(cString: filename.assumingMemoryBound(to: CChar.self))) {
        return .init(image)
    }
    return nil
}

@_cdecl("MSCloseImage")
public func MSCloseImage(_ image: UnsafeRawPointer) {
    // no-op
}

@_cdecl("MSFindSymbol")
public func MSFindSymbol(_ image: UnsafeRawPointer?, _ name: UnsafeRawPointer?) -> UnsafeRawPointer? {
    guard let name else { return nil }
    
    if let image {
        
        let swiftName = String(cString: name.assumingMemoryBound(to: CChar.self))
        
        #if os(macOS)
        if let symbol = try? ellekit.findSymbol(image: image, symbol: swiftName) {
            return .init(symbol)
        }
        #else
        if let symbol = try? ellekit.findSymbol(image: image, symbol: swiftName) {
            return .init(symbol)
        }
        if #available(iOS 14.0, tvOS 14.0, watchOS 7.0, *) {
            var info = Dl_info()
            dladdr(image, &info)
            if info.dli_fname != nil && _dyld_shared_cache_contains_path(info.dli_fname) {
                if let symbol = try? ellekit.findPrivateSymbol(image: image, symbol: swiftName) {
                    return .init(symbol)
                }
            }
        } else {
            if let symbol = try? ellekit.findPrivateSymbol(image: image, symbol: swiftName) {
                return .init(symbol)
            }
        }
        #endif
    } else {
        fputs("[-] ellekit: image=null, global search (slow) for symbol: \(String(cString: name.assumingMemoryBound(to: CChar.self)))\n", stderr)
        for img in 0..<_dyld_image_count() {
            if let hdr = _dyld_get_image_header(img) {
                if let result = MSFindSymbol(hdr, name) {
                    return result
                }
            }
        }
    }
    return nil
}

@_cdecl("MSHookFunction")
public func MSHookFunction(_ symbol: UnsafeMutableRawPointer, _ replace: UnsafeMutableRawPointer, _ result: UnsafeMutablePointer<UnsafeMutableRawPointer?>?) {
    hook(symbol, replace, result)
}

@_cdecl("MSHookClassPair")
public func MSHookClassPair(_ targetClass: AnyClass, _ hookClass: AnyClass, _ stubClass: AnyClass?) {
    hookClassPair(targetClass, hookClass, stubClass)
}

@_cdecl("MSHookMessageEx")
public func MSHookMessageEx(_ cls: AnyClass, _ sel: Selector, _ imp: IMP, _ result: UnsafeMutablePointer<UnsafeMutableRawPointer?>?) {
    messageHook(cls, sel, imp, result)
}

@_cdecl("MSHookMemory")
public func MSHookMemory(_ target: UnsafeMutableRawPointer, _ code: UnsafeMutableRawPointer, _ size: mach_vm_size_t) {
    rawHook(address: target.makeReadable(), code: code.makeReadable().assumingMemoryBound(to: UInt8.self), size: size)
}

@_cdecl("MSHookIvar")
public func MSHookIvar(_ object: AnyObject?, _ name: UnsafePointer<CChar>?) -> UnsafeMutableRawPointer? {
    let ptr: UnsafeMutablePointer<Any>? = hookIvar(object, name)
    if let ptr {
        return .init(ptr)
    } else {
        return nil
    }
}
