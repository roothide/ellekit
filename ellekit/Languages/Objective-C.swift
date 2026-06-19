
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

#warning("TODO: Unhook API")

@inlinable
public func messageHook(_ cls: AnyClass, _ sel: Selector, _ imp: IMP, _ result: UnsafeMutablePointer<UnsafeMutableRawPointer?>?) {

    guard let method = class_getInstanceMethod(cls, sel) else {
        return
    }

    let old = class_replaceMethod(cls, sel, .init(UnsafeMutableRawPointer(imp).makeCallable()), method_getTypeEncoding(method))

    if let result {
        if let old,
           let fp = unsafeBitCast(old, to: UnsafeMutableRawPointer?.self) {
            print("[+] ellekit: Successfully got orig pointer for an objc message hook")
            result.pointee = fp.makeCallable()
        } else if let superclass = class_getSuperclass(cls),
                  let ptr = class_getMethodImplementation(superclass, sel),
                  let fp = unsafeBitCast(ptr, to: UnsafeMutableRawPointer?.self) {
            print("[+] ellekit: Successfully got orig pointer from superclass for an objc message hook")
            result.pointee = fp.makeCallable()
        }
    }
}

@inlinable
func hookIvar<T>(_ object: AnyObject?, _ name: UnsafePointer<CChar>?) -> UnsafeMutablePointer<T>? {
    guard let object, let name, let cls = object_getClass(object) else { return nil }
    let ivar = class_getInstanceVariable(cls, name)
    if let ivar {
        let ptr = Unmanaged.passUnretained(object).toOpaque().advanced(by: ivar_getOffset(ivar))
        return ptr.assumingMemoryBound(to: T.self)
    }
    return nil
}

// MSHookClassPair
// thanks to faptain kink
@inlinable
public func hookClassPair(_ targetClass: AnyClass, _ hookClass: AnyClass, _ stubClass: AnyClass?) {
    var method_count: UInt32 = 0
    guard let methods = class_copyMethodList(hookClass, &method_count) else {
        return
    }
    print("[*] ellekit: \(method_count) methods found in hooked class")
    for iter in 0..<Int(method_count) {
        let selector = method_getName(methods[iter])
        print(["[*] ellekit: hooked method is", sel_getName(selector)])
        
        let hookImp = method_getImplementation(methods[iter])
        let hookType = method_getTypeEncoding(methods[iter])
        
        if let original = class_getInstanceMethod(targetClass, selector) {
            if let stubClass {
                class_replaceMethod(stubClass, selector, method_getImplementation(original), method_getTypeEncoding(original))
            }
            class_replaceMethod(targetClass, selector, hookImp, hookType)
        } else {
            class_addMethod(targetClass, selector, hookImp, hookType)
        }
    }
    
    free(methods)
}
