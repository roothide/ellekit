
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation

func getAllThreads() -> [thread_act_t] {
    var threadList: thread_act_array_t?
    var threadCount = mach_msg_type_number_t(0)

    let kr = task_threads(mach_task_self_, &threadList, &threadCount)
    guard kr == KERN_SUCCESS, let threadList else {
        return []
    }

    let threads = Array(
        UnsafeBufferPointer(start: threadList, count: Int(threadCount))
    )

    let size = vm_size_t(threadCount) * vm_size_t(MemoryLayout<thread_act_t>.stride)
    vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: threadList)), size)

    return threads
}

public func stopAllThreads() -> [thread_act_t] {
    guard enforceThreadSafety else { return [] }

    let task = mach_task_self_
    let currentThread = mach_thread_self()
    defer {
        mach_port_deallocate(task, currentThread)
    }

    var threads = getAllThreads()

    threads.removeAll { thread in
        if thread == currentThread {
            mach_port_deallocate(task, thread)
            return true
        }

        let kr = thread_suspend(thread)
        if kr != KERN_SUCCESS {
            mach_port_deallocate(task, thread)
            return true
        }

        return false
    }

    return threads
}

public func resumeAllThreads(_ threads: [thread_act_t]) {
    guard enforceThreadSafety else { return }
    threads.forEach {
        thread_resume($0)
        mach_port_deallocate(mach_task_self_, $0)
    }
}
