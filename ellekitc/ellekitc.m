
// This file is licensed under the BSD-3 Clause License
// Copyright 2022 © Charlotte Belanger

#if __arm64e__
#include <ptrauth.h>
#endif

#include <mach/message.h>

// MARK: - PAC

void* sign_pointer(void* ptr) {
#if __has_feature(ptrauth_calls)
    return ptrauth_sign_unauthenticated(ptrauth_strip(ptr, ptrauth_key_function_pointer), ptrauth_key_function_pointer, 0);
#else
    return ptr;
#endif
}

void* sign_pc(void* ptr) {
#if __has_feature(ptrauth_calls)
    return ptrauth_sign_unauthenticated(ptr, ptrauth_key_process_independent_code, 0x7481);
#else
    return ptr;
#endif
}

void* strip_pointer(void* ptr) {
#if __has_feature(ptrauth_calls)
    return ptrauth_strip(ptr, ptrauth_key_function_pointer);
#else
    return ptr;
#endif
}

extern int shared_region_check(void* address);

#include <stdarg.h>
#include <sys/types.h>
#include <string.h>
#include <sys/fcntl.h>

// This is taken from tihmstar/jbinit, because I don't write C, and I can't use va_list in Swift

extern int sandbox_check_by_audit_token(audit_token_t au, const char *operation, int sandbox_filter_type, ...);

extern int hook_sandbox_check(audit_token_t au, const char *operation, int sandbox_filter_type, ...);
int hook_sandbox_check(audit_token_t au, const char *operation, int sandbox_filter_type, ...) {
    va_list a;
    va_start(a, sandbox_filter_type);
    const char *name = va_arg(a, const char *);
    const void *arg2 = va_arg(a, void *);
    const void *arg3 = va_arg(a, void *);
    const void *arg4 = va_arg(a, void *);
    const void *arg5 = va_arg(a, void *);
    const void *arg6 = va_arg(a, void *);
    const void *arg7 = va_arg(a, void *);
    const void *arg8 = va_arg(a, void *);
    const void *arg9 = va_arg(a, void *);
    const void *arg10 = va_arg(a, void *);
    va_end(a);
    if (name && operation) {
        if (strcmp(operation, "mach-lookup") == 0) {
            if (strncmp((char *)name, "cy:", 3) == 0 || strncmp((char *)name, "lh:", 3) == 0) {
                /* always allow */
                return 0;
            }
        }
    }
    return sandbox_check_by_audit_token(au, operation, sandbox_filter_type, name, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

#include <mach/arm/kern_return.h>
#include <mach/port.h>
#include <mach/vm_prot.h>

__attribute__((noinline, naked)) volatile kern_return_t custom_mach_vm_protect(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
#if __arm64__
    __asm("mov x16, #0xFFFFFFFFFFFFFFF2");
    __asm("svc 0x80");
    __asm("ret");
#else
    __asm(".intel_syntax noprefix; \
           mov rax, 0xFFFFFFFFFFFFFFF2; \
           syscall; \
           ret");
#endif
}

void manual_memcpy(void *restrict dest, const void *src, size_t len) {
    volatile uint8_t *d8 = dest;
    const uint8_t *s8 = src;
    while (len--)
        *d8++ = *s8++;
}


#include <mach/mach.h>
#include <sys/mman.h>
#include <assert.h>
#include <Foundation/Foundation.h>
#include <dlfcn.h>

void* addrs[100] = {0};
volatile int vvvvv=0;

#include <pthread.h>
void* thread_main(void*)
{
    while(true) {
        usleep(1000*10);
        for(int i=0; i<100; i++) {
            if(addrs[i]) {
                asm("dmb sy");
                vvvvv += *(int*)addrs[i];
            } else {
                break;
            }
        }
    }
    
    return NULL;
}

int64_t (*jbdswLockDSCPage)(uint64_t addr, uint64_t size);

#define NSLog(...)
#define mincore(...)    0

int memlock(void* addr, int size)
{
    NSArray* blacklist = @[
        @"logd",
        @"cfprefsd",
        @"backboardd",
        @"identityservicesd",
        @"maild",
        @"imagent",
        @"notifyd",
        @"analyticsd",
        @"sharingd",
        @"IMDPersistenceAgent",
    ];
    
    if( [blacklist containsObject:NSProcessInfo.processInfo.processName] ) return 0;
    
    
//    static int init=0;
//    if(init++==0) {
//        pthread_t thread;
//        pthread_create(&thread, NULL, thread_main, NULL);
//    }
    
    volatile int val=*(int*)addr;
    
    unsigned char v0[1]={0};
    if(mincore(addr, size, v0) != 0) {
        NSLog(@"memlock: mincore error %d,%s", errno, strerror(errno));
        return -2;
    }
    
    void* newaddr = NULL;
    vm_prot_t cur_prot=0;
    vm_prot_t max_prot=0;
    
    struct dl_info di={0};
    NSLog(@"memlock: dladdr %p,%x : %d, %s : %s", addr, size, dladdr(addr, &di), di.dli_sname, di.dli_fname);
    
    kern_return_t kr = vm_remap(mach_task_self(), &newaddr, size, 0, VM_FLAGS_ANYWHERE,
                                            mach_task_self(), addr, 0, &cur_prot, &max_prot, VM_INHERIT_SHARE);
    
    if(kr != KERN_SUCCESS) {
        NSLog(@"memlock: remap error %d,%s", kr, mach_error_string(kr));
        return -1;
    }
    
    unsigned char v1[1]={0};
    if(mincore(newaddr, size, v1) != 0) {
        NSLog(@"memlock: mincore error %d,%s", errno, strerror(errno));
        return -2;
    }
    
    NSLog(@"memlock: remap %p %x %x", newaddr, cur_prot, max_prot);
    
    size += ((uint64_t)addr) & (PAGE_SIZE-1);
    NSLog(@"memlock: newsize %p=>%p : %x", addr, newaddr, size);
    
    if(madvise(newaddr, size, MADV_WILLNEED) != 0) {
        NSLog(@"memlock: madvise error %d,%s", errno, strerror(errno));
        return -2;
    }
    
     val = *(int*)newaddr;
    
    unsigned char v2[1]={0};
    if(mincore(newaddr, size, v2) != 0) {
        NSLog(@"memlock: mincore error %d,%s", errno, strerror(errno));
        return -2;
    }
    
//    if(mlock(newaddr, size) != 0) {
//        NSLog(@"memlock: mlock error %d,%s", errno, strerror(errno));
//        return -3;
//    }
    
//    kr = mach_vm_wire(mach_host_self(), mach_task_self(), newaddr, size, cur_prot);
//    if(kr != KERN_SUCCESS) {
//        NSLog(@"memlock: wire error %d,%s", kr, mach_error_string(kr));
//        return -1;
//    }
    
    unsigned char v3[1]={0};
    if(mincore(newaddr, size, v3) != 0) {
        NSLog(@"memlock: mincore error %d,%s", errno, strerror(errno));
        return -2;
    }
    
    for(int i=0; i<100; i++) {
        if(!addrs[i]) {
            addrs[i] = newaddr;
            break;
        }
    }
    //sleep(1);
    
    val = *(int*)newaddr;
    
    unsigned char v4[1]={0};
    if(mincore(newaddr, size, v4) != 0) {
        NSLog(@"memlock: mincore error %d,%s", errno, strerror(errno));
        return -2;
    }
    
    val = *(int*)newaddr;
    
    NSLog(@"memlock: vector = %x %x %x %x %x, %08X", v0[0], v1[0], v2[0], v3[0], v4[0], val);
    
    return val;
    
//    kernel_version_t version={0};
//    NSLog(@"memlock: version=%d, %s", host_kernel_version(mach_host_self(), version), version);
//
//    kr = mach_vm_wire(mach_host_self(), mach_task_self(), newaddr, size, cur_prot);
//
//    NSLog(@"memlock: %p %p %x : %d,%s", addr, newaddr, size, kr, mach_error_string(kr));

//    if(kr != KERN_SUCCESS)
//    {
//        if(!jbdswLockDSCPage) jbdswLockDSCPage = dlsym(RTLD_DEFAULT, "jbdswLockDSCPage");
//
//        int locked = jbdswLockDSCPage((uint64_t)newaddr, size);
//
//        NSLog(@"memlock: locked=%d", locked);
//
//        return locked;
//    }
    
    return 0;
}
