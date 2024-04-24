
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

#include "injector.h"

#include <CoreFoundation/CoreFoundation.h>
#include <objc/runtime.h>
#include <dirent.h>
#include <dlfcn.h>
#include <os/log.h>
#include <mach-o/dyld.h>
#include <roothide/roothide.h>

bool g_isUIProcess = false;

#define PROC_PIDPATHINFO_MAXSIZE  (1024)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

extern void NSLog(CFStringRef, ...);

static bool rootless = false;

static int filter_dylib(const struct dirent *entry) {
    char* dot = strrchr(entry->d_name, '.');
    return dot && strcmp(dot + 1, "dylib") == 0;
}

static int isApp(const char* path) {
    char* dot = strrchr(path, '.');
    return dot && memcmp(dot + 1, "app", 4) == 0;
}

#if TARGET_OS_OSX
#define TWEAKS_DIRECTORY "/Library/TweakInject/"
#else
#define TWEAKS_DIRECTORY_ROOTFUL "/usr/lib/TweakInject/"
#define TWEAKS_DIRECTORY_ROOTLESS jbroot("/usr/lib/TweakInject/")
#define MOBILESAFETY_PATH_ROOTFUL "/usr/lib/ellekit/MobileSafety.dylib"
#define MOBILESAFETY_PATH_ROOTLESS jbroot("/usr/lib/ellekit/MobileSafety.dylib")
#define OLDABI_PATH_ROOTFUL "/usr/lib/ellekit/OldABI.dylib"
#define OLDABI_PATH_ROOTLESS jbroot("/usr/lib/ellekit/OldABI.dylib")
#endif

char* append_str(const char* str, const char* append_str) {
    size_t str_len = strlen(str);
    size_t append_str_len = strlen(append_str);

    char* new_str = malloc(str_len + append_str_len + 1);  // allocate memory for the new string
    if (new_str == NULL) {
        return NULL;  // allocation failed
    }

    memcpy(new_str, str, str_len); // copy the original string to the new string
    strncpy(new_str + str_len, append_str, append_str_len); // append the new string to the end
    new_str[str_len + append_str_len] = '\0';  // terminate the new string

    return new_str;
}

char *get_last_path_component(const char *path)
{
    char *last_component = strrchr(path, '/');
    if (last_component == NULL) {
        return NULL;
    }
    return last_component + 1;
}

#define MAX_TWEAKMANAGERS 20 // this is very reasonable
char* tweakManagers[MAX_TWEAKMANAGERS]={0};
int tweakManagers_count=0;

#define MAX_TWEAKS 1000
char* tweaks[MAX_TWEAKS]={0};
int tweaks_count=0;

static bool tweak_needinject(const char* orig_path, bool* isTweakManager) {
    
    CFStringRef plistPath;
    CFURLRef url;
    CFDataRef data;
    CFPropertyListRef plist;
    
    char* path = append_str(orig_path, ".plist");
        
    plistPath = CFStringCreateWithCString(kCFAllocatorDefault, path, kCFStringEncodingUTF8);

    if (access(path, F_OK) != F_OK) {
        free(path);
        CFRelease(plistPath);
        return false;
    }
    
    free(path);
    
    url = CFURLCreateWithFileSystemPath(kCFAllocatorSystemDefault, plistPath, kCFURLPOSIXPathStyle, false);
        
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (url && CFURLCreateDataAndPropertiesFromResource(kCFAllocatorSystemDefault, url, &data, NULL, NULL, NULL)) {
#pragma clang diagnostic pop
        plist = CFPropertyListCreateWithData(kCFAllocatorSystemDefault, data, kCFPropertyListImmutable, NULL, NULL);
        CFRelease(data);
    } else {
        if (url) {
            CFRelease(url);
        }
        CFRelease(plistPath);
        return false;
    }
    CFRelease(url);
    CFRelease(plistPath);
                            
    CFDictionaryRef filter = CFDictionaryGetValue(plist, CFSTR("Filter"));
    
    CFBooleanRef tweakManager = CFDictionaryGetValue(plist, CFSTR("IsTweakManager"));
    
    if (tweakManager != NULL) {
        *isTweakManager = CFBooleanGetValue(tweakManager);
    }

    CFArrayRef versions = CFDictionaryGetValue(filter, CFSTR("CoreFoundationVersion"));
    if (versions) {

        if (CFArrayGetCount(versions) == 1) {
            CFTypeRef value = CFArrayGetValueAtIndex(versions, 0);
            if (CFGetTypeID(value) == CFNumberGetTypeID()) {
                double version;
                CFNumberGetValue((CFNumberRef)value, kCFNumberDoubleType, &version);
                if (version > kCFCoreFoundationVersionNumber) {
                    CFRelease(plist);
                    return false;
                }
            }
        }
        
        if (CFArrayGetCount(versions) == 2) {
            CFTypeRef value1 = CFArrayGetValueAtIndex(versions, 0);
            CFTypeRef value2 = CFArrayGetValueAtIndex(versions, 0);
            if (CFGetTypeID(value1) == CFNumberGetTypeID() || CFGetTypeID(value2) == CFNumberGetTypeID()) {
                double version1;
                double version2;
                CFNumberGetValue((CFNumberRef)value1, kCFNumberDoubleType, &version1);
                CFNumberGetValue((CFNumberRef)value2, kCFNumberDoubleType, &version2);
                if (version1 > kCFCoreFoundationVersionNumber || version2 <= kCFCoreFoundationVersionNumber) {
                    CFRelease(plist);
                    return false;
                }
            }
        }
    }

    CFArrayRef bundles = CFDictionaryGetValue(filter, CFSTR("Bundles"));
    
    if (bundles) {
        for (CFIndex i = 0; i < CFArrayGetCount(bundles); i++) {
            CFStringRef id = CFArrayGetValueAtIndex(bundles, i);
            if (id) {
                
                if(!g_isUIProcess) {
                    const char* bid = CFStringGetCStringPtr(id, kCFStringEncodingUTF8);
                    if(!bid) continue;
                    
                    if(strncmp(bid, "com.apple.UIKit", sizeof("com.apple.UIKit")-1)==0 // and com.apple.UIKitCore
                       || strncmp(bid, "com.apple.TextInput", sizeof("com.apple.TextInput")-1)==0 // and com.apple.TextInputUI
                       || strncmp(bid, "com.apple.TextEntry", sizeof("com.apple.TextEntry")-1)==0
                       //for what in libhooker's tweakloader ? || strncmp(bid, "UI", sizeof("UI")-1)==0
                       ){
                        continue;
                    }
                }
                
                CFBundleRef bundle = CFBundleGetBundleWithIdentifier(id);
                if (bundle
                    && CFBundleIsExecutableLoaded(bundle)
                    ) {
                    goto success;
                }

//                CFMutableStringRef lowercased = CFStringCreateMutableCopy(NULL, 0, id);
//                CFStringLowercase(lowercased, NULL);
//                if (CFBundleGetBundleWithIdentifier(lowercased)) {
//                    CFRelease(lowercased);
//                    goto success;
//                }
//                CFRelease(lowercased);
            }
        }
    }
    
    CFArrayRef classes = CFDictionaryGetValue(filter, CFSTR("Classes"));
    
    if (classes) {
        for (CFIndex i = 0; i < CFArrayGetCount(classes); i++) {
            CFStringRef id = CFArrayGetValueAtIndex(classes, i);
            const char* str = CFStringGetCStringPtr(id, kCFStringEncodingASCII);
            if (str) {
                if (objc_getClass(str)) {
                    goto success;
                }
            }
            else {
                char* copiedStr = malloc(CFStringGetLength(id)+1);
                CFStringGetCString(id, copiedStr, CFStringGetLength(id)+1, kCFStringEncodingASCII);
                if (objc_getClass(copiedStr)) {
                    free(copiedStr);
                    goto success;
                }
                free(copiedStr);
            }
        }
    }
    
    CFArrayRef executables = CFDictionaryGetValue(filter, CFSTR("Executables"));

    if (executables) {
        
        char executable[1024];
        uint32_t size = 1024;

        if (_NSGetExecutablePath(executable, &size) == 0) {
            
            for (CFIndex i = 0; i < CFArrayGetCount(executables); i++) {
                CFStringRef id = CFArrayGetValueAtIndex(executables, i);
                const char* str = CFStringGetCStringPtr(id, kCFStringEncodingASCII);
                if (str) {
                    if (!strcmp(str, get_last_path_component(executable))) {
                        goto success;
                    }
                }
                else {
                    char* copiedStr = malloc(CFStringGetLength(id)+1);
                    CFStringGetCString(id, copiedStr, CFStringGetLength(id)+1, kCFStringEncodingASCII);
                    if (!strcmp(copiedStr, get_last_path_component(executable))) {
                        free(copiedStr);
                        goto success;
                    }
                    free(copiedStr);
                }
            }
        } else if (CFBundleGetMainBundle()) {
            CFBundleRef bundle = CFBundleGetMainBundle();
            CFURLRef url = CFBundleCopyExecutableURL(bundle);
            if (url) {
                CFStringRef file_name = CFURLCopyLastPathComponent(url);
                if (file_name) {
                    for (CFIndex i = 0; i < CFArrayGetCount(executables); i++) {
                        CFStringRef id = CFArrayGetValueAtIndex(executables, i);
                        if (CFStringCompare(file_name, id, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                            CFRelease(file_name);
                            CFRelease(url);
                            goto success;
                        }
                    }
                    CFRelease(file_name);
                }
                CFRelease(url);
            }
        }
    }
    
    CFRelease(plist);
    return false;
    
success:
    CFRelease(plist);
    return true;
}

int
alphasort2 (const struct dirent **a, const struct dirent **b)
{
  return -strcoll ((*a)->d_name, (*b)->d_name);
}

static void tweaks_iterate(void) {
    struct dirent **files;
    int n;

    if (rootless) {
        n = scandir(TWEAKS_DIRECTORY_ROOTLESS, &files, filter_dylib, alphasort2);
    } else {
        n = scandir(TWEAKS_DIRECTORY_ROOTFUL, &files, filter_dylib, alphasort2);
    }
    if (n == -1) {
        perror("scandir");
        return;
    }

    while (n--) {
        
        if (*(files[n]->d_name)) {
            char* full_path;
            if (rootless) {
                full_path = append_str(TWEAKS_DIRECTORY_ROOTLESS, files[n]->d_name);
            } else {
                full_path = append_str(TWEAKS_DIRECTORY_ROOTFUL, files[n]->d_name);
            }
            char* plist = strndup(full_path, strlen(full_path) - 6);
            
            bool isTweakManager = false;
            bool ret = tweak_needinject(plist, &isTweakManager);
                        
            if (ret) {
                if (isTweakManager) {
                    if(tweakManagers_count < MAX_TWEAKMANAGERS) {
                        tweakManagers[tweakManagers_count] = strdup(full_path);
                        tweakManagers_count++;
                    }
                } else {
                    if(tweaks_count < MAX_TWEAKS) {
                        tweaks[tweaks_count] = strdup(full_path);
                        tweaks_count++;
                    }
                }
            }
            
            free(full_path);
            free(plist);
            free(files[n]);
        }
    }
    
    if(tweaks_count) {
        for (int i = 0; i < tweakManagers_count; i++) {
            dlopen(tweakManagers[i], RTLD_LAZY);
            free(tweakManagers[i]);
            tweakManagers[i] = NULL;
        }

#if !TARGET_OS_OSX
        if (rootless) {
            if (!access(OLDABI_PATH_ROOTLESS, F_OK)) {
                dlopen(OLDABI_PATH_ROOTLESS, RTLD_LAZY);
            }
        } else {
            if (!access(OLDABI_PATH_ROOTFUL, F_OK)) {
                dlopen(OLDABI_PATH_ROOTFUL, RTLD_LAZY);
            }
        }
#endif

        for (int i = 0; i < tweaks_count; i++) {
            dlopen(tweaks[i], RTLD_LAZY);
            free(tweaks[i]);
            tweaks[i] = NULL;
        }
    }
    
    free(files);
}

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
bool isAppPath( char* path)
{
    if(strncmp(path, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return false;

    char* p1 = path + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return false;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return false;

    return true;
}

__attribute__((constructor))
static void injection_init(void) {
    
    char* msSafe = getenv("_MSSafeMode");
    if (msSafe && atoi(msSafe) == 1) {
        return;
    }
    
    char* safe = getenv("_SafeMode");
    if (safe && atoi(safe) == 1) {
        return;
    }
    
#if !TARGET_OS_OSX
    
    //if (!access("/var/jb/usr/lib/ellekit/libinjector.dylib", F_OK))
    {
        rootless = true;
    }
    
    if (CFBundleGetMainBundle() && CFBundleGetIdentifier(CFBundleGetMainBundle())) {
        if (CFEqual(CFBundleGetIdentifier(CFBundleGetMainBundle()), CFSTR("com.apple.springboard"))) {
            
            g_isUIProcess = true;
            
            if (rootless) {
                dlopen(MOBILESAFETY_PATH_ROOTLESS, RTLD_NOW);
            } else {
                dlopen(MOBILESAFETY_PATH_ROOTFUL, RTLD_NOW);
            }
        }
    }
    
    if (!access(jbroot("/var/mobile/.eksafemode"), F_OK)) {
        return;
    }
#endif
    
    const char* extension = getenv("SANDBOX_EXTENSION");
    if (extension) {
        sandbox_extension_consume(extension);
    }
    
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (proc_pidpath(getpid(), pathbuf, sizeof(pathbuf)) > 0) {
        if(isAppPath(pathbuf) || strstr(pathbuf, "/Applications/")
           || strcmp(pathbuf, "/System/Library/CoreServices/SpringBoard.app/SpringBoard")==0)
            g_isUIProcess = true;
    }
    
    tweaks_iterate();
}
