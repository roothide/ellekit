
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

import Foundation
import MachO

public func openImage(image path: String) throws -> UnsafePointer<mach_header>?
{
    var want = stat()
    var useInode = false
    
    //fast check
    guard let handler = dlopen(path, RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD) else {
        return nil
    }
    defer { dlclose(handler) }

    if #available(iOS 14.0, macOS 11.0, *), _dyld_shared_cache_contains_path(path) {
        useInode = false
    } else {
        //slow path
        useInode = (stat(path, &want) == 0)
    }

    for i in 0..<_dyld_image_count() {
        guard let name = _dyld_get_image_name(i) else { continue }

        if strcmp(name, path) == 0 {
            return _dyld_get_image_header(i)
        }
        
        if useInode {
            var st = stat()
            if stat(name, &st) == 0, st.st_dev == want.st_dev, st.st_ino == want.st_ino {
                return _dyld_get_image_header(i)
            }
        }
    }
    
    return nil
}
