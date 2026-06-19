
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation
import Darwin
import os.log

// target:replacement. Private: access only through withHooksLock, which hands it to the closure.
private var hooks: [UnsafeMutableRawPointer: UnsafeMutableRawPointer] = [:]

// Darwin pthread_impl.h: _PTHREAD_MUTEX_SIG_init, used by PTHREAD_MUTEX_INITIALIZER.
private let pthreadMutexStaticInitializerSignature = 0x32AAABA7

private var hooksMutex: pthread_mutex_t = {
    var mutex = pthread_mutex_t()
    mutex.__sig = pthreadMutexStaticInitializerSignature
    return mutex
}()

@discardableResult
func withHooksLock<T>(_ body: (inout [UnsafeMutableRawPointer: UnsafeMutableRawPointer]) throws -> T) rethrows -> T {
    pthread_mutex_lock(&hooksMutex)
    defer { pthread_mutex_unlock(&hooksMutex) }
    return try body(&hooks)
}

public var exceptionHandler: ExceptionHandler?

public var enforceThreadSafety: Bool = true

@_cdecl("EKEnableThreadSafety")
public func EKEnableThreadSafety(_ on: Int) {
    enforceThreadSafety = on == 1
}
