
// WARNING:
// This code is taken from Accord
// It is therefore licensed under the BSD 4 clause license
// Copyright 2022, Evelyn Belanger

import Foundation
import os.log

private let ENABLE_SYSLOGGER: Bool = false
private let ENABLE_LINE_LOGGING: Bool = true
private let ENABLE_FILE_EXTENSION_LOGGING: Bool = true

@available(iOS 14.0, tvOS 14.0, watchOS 8.0, macOS 11.0, *)
public let syslogger = { ENABLE_SYSLOGGER ? Logger(subsystem: "red.charlotte.ellekit", category: "all") : nil }()

@inline(__always)
public func dprint(
    _ items: Any..., // first variadic parameter
    file: String = #fileID, // file name which is not meant to be specified
    _ items2: Any..., // second variadic parameter
    line: Int = #line, // line number
    separator: String = " "
) {
#if DEBUG
    let file = ENABLE_FILE_EXTENSION_LOGGING ?
        file.components(separatedBy: "/").last ?? "ElleKit" :
        file.components(separatedBy: "/").last?.components(separatedBy: ".").first ?? "ElleKit"
    let line = ENABLE_LINE_LOGGING ? ":\(String(line))" : ""
    log(items: items, file: file, line: line, separator: separator)
#endif
}

#if DEBUG
struct FileLog: TextOutputStream {

    static var shared = FileLog()
    
    private var enableLogging: Bool {
        #if !os(macOS)
        FileManager.default.fileExists(atPath: ("/private/var/mobile/.ekenablelogging"))
        #else
        FileManager.default.fileExists(atPath: "/Library/TweakInject/.ekenablelogging")
        #endif
    }
    
    func write(_ string: String) {
        #if os(iOS)
        let log = NSURL.fileURL(withPath: ("/var/mobile/log.txt" as NSString).resolvingSymlinksInPath)
        #else
        let log = NSURL.fileURL(withPath: "/Users/charlotte/log.txt")
        #endif
        if let handle = try? FileHandle(forWritingTo: log) {
            handle.seekToEndOfFile()
            handle.write((string+"\n").data(using: .utf8)!)
            handle.closeFile()
        } else {
            try? string.data(using: .utf8)?.write(to: log)
        }
    }
}
#endif

@inline(__always)
public func tprint(
    _ items: Any..., // first variadic parameter
    file: String = #fileID, // file name which is not meant to be specified
    _ items2: Any..., // second variadic parameter
    line: Int = #line, // line number
    separator: String = " "
) {
#if DEBUG
    let file = ENABLE_FILE_EXTENSION_LOGGING ?
        file.components(separatedBy: "/").last ?? "ElleKit" :
        file.components(separatedBy: "/").last?.components(separatedBy: ".").first ?? "ElleKit"
    let line = ENABLE_LINE_LOGGING ? ":\(String(line))" : ""
    var out = String()
    for item in items {
        if type(of: item) is AnyClass {
            out.append(String(reflecting: item))
        } else if let data = item as? Data {
            out.append(String(data: data, encoding: .utf8) ?? String(describing: item))
        } else {
            out.append(String(describing: item))
        }
        out.append(separator)
    }
    FileLog.shared.write("[\(file)\(line)] \(out)")
#endif
}

@available(*, deprecated, message: "Multi-argument print is disabled. Use print(\"...\") with a single interpolated string.")
public func print(
    _ first: Any,
    _ second: Any,
    _ rest: Any...,
    separator: String = " ",
    terminator: String = "\n"
) {
}

// this function exists to override the print function
// when there is only one item to print
// since the other function uses two variadic parameters it doesn't work
// when there is one element
@inline(__always)
public func print(
    _ item: @autoclosure () -> Any,
    file: String = #fileID,
    line: Int = #line
) {
#if DEBUG
    let file = ENABLE_FILE_EXTENSION_LOGGING ?
        file.components(separatedBy: "/").last ?? "ElleKit" :
        file.components(separatedBy: "/").last?.components(separatedBy: ".").first ?? "ElleKit"
    let line = ENABLE_LINE_LOGGING ? ":\(String(line))" : ""
    log(items: [item()], file: file, line: line)
#endif
}

var islogd: Bool = {
    ProcessInfo.processInfo.processName.contains("logd")
}()

@inline(__always)
private func log<T>(items: [T], file: String, line: String? = nil, separator: String = " ") {
#if DEBUG
    var out = String()
    for item in items {
        if type(of: item) is AnyClass {
            out.append(String(reflecting: item))
        } else if let data = item as? Data {
            out.append(String(data: data, encoding: .utf8) ?? String(describing: item))
        } else {
            out.append(String(describing: item))
        }
        out.append(separator)
    }
    if getenv("ELLEKITLOG") != nil {
        fputs("[\(file)\(line ?? "")] \(out)\n", stderr)
    }
    if #available(iOS 14.0, tvOS 14.0, watchOS 8.0, macOS 11.0, *) {
        if ENABLE_SYSLOGGER && !islogd {
            syslogger?.log("[\(file)\(line ?? "")] \(out)")
        }
    }
#endif
}
