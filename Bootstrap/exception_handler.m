//
//  main.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 24/10/25.
//

#import <UIKit/UIKit.h>
@import MachO;
#import <os/lock.h>
#import "AppDelegate.h"
#include "taskporthaxx.h"
#include <sys/sysctl.h>
#include <stdatomic.h>
#include <string.h>
// These are provided by mig
#include "mach_exc.h"
#include "mach_excServer.h"
// threading vars
static pthread_mutex_t pac_mutex = PTHREAD_MUTEX_INITIALIZER;
_Atomic bool global_found = false;
_Atomic uint64_t global_result_ptr = 0;
_Atomic uint32_t global_result_diversifier = 0;
static uint64_t base_count = 0;
static int ncpu = 1;

static _Thread_local int current_thread_id = 0;
static _Thread_local sem_t local_sem_input_ready;
static _Thread_local sem_t local_sem_output_ready;
static _Thread_local arm_thread_state64_internal *local_new_state;

struct thread_info {
    mach_port_t port;
    uint64_t count;
    int thread_id;
    sem_t sem_input_ready;
    sem_t sem_output_ready;
    int num_exceptions_handled;
    arm_thread_state64_internal *new_state;
};
static struct thread_info threads[16];
static int num_threads = 0;

static struct thread_info *get_thread_info(mach_port_t port) {
    for (int i = 0; i < num_threads; i++) {
        if (threads[i].port == port) {
            return &threads[i];
        }
    }
    return &threads[0]; // fallback
}

static int get_cpu_count(void) {
    int mib[2] = {CTL_HW, HW_NCPU};
    int count = 1;
    size_t len = sizeof(count);
    sysctl(mib, 2, &count, &len, NULL, 0);
    return count > 0 ? count : 1;
}

mach_port_t setup_exception_server_with_id(int thread_id);

uintptr_t brX8Address, changeLRAddress, paciaAddress;
BOOL wantsDetach;
mach_port_t GlobalChildTaskPort;
mach_port_t GlobalChildThreadPort;
uint64_t signed_pointer;
uint32_t signed_diversifier;

struct dyld_all_image_infos *_alt_dyld_get_all_image_infos(void) {
    static struct dyld_all_image_infos *result;
    if (result) {
        return result;
    }
    struct task_dyld_info dyld_info;
    mach_vm_address_t image_infos;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kern_return_t ret;
    ret = task_info(mach_task_self_,
                    TASK_DYLD_INFO,
                    (task_info_t)&dyld_info,
                    &count);
    if (ret != KERN_SUCCESS) {
        return NULL;
    }
    image_infos = dyld_info.all_image_info_addr;
    result = (struct dyld_all_image_infos *)image_infos;
    return result;
}

void DumpRegisters(const arm_thread_state64_internal *old_state) {
    NSLog(@"Registers:\n"
           " x0: 0x%016llx  x1: 0x%016llx  x2: 0x%016llx  x3: 0x%016llx\n"
           " x4: 0x%016llx  x5: 0x%016llx  x6: 0x%016llx  x7: 0x%016llx\n"
           " x8: 0x%016llx  x9: 0x%016llx x10: 0x%016llx x11: 0x%016llx\n"
           "x12: 0x%016llx x13: 0x%016llx x14: 0x%016llx x15: 0x%016llx\n"
           "x16: 0x%016llx x17: 0x%016llx x18: 0x%016llx x19: 0x%016llx\n"
           "x20: 0x%016llx x21: 0x%016llx x22: 0x%016llx x23: 0x%016llx\n"
           "x24: 0x%016llx x25: 0x%016llx x26: 0x%016llx x27: 0x%016llx\n"
           "x28: 0x%016llx  fp: 0x%016llx  lr: 0x%016llx\n"
           " pc: 0x%016llx  sp: 0x%016llx psr: 0x%08x"
           "\n",
           old_state->__x[ 0], old_state->__x[ 1], old_state->__x[ 2], old_state->__x[ 3], old_state->__x[ 4], old_state->__x[ 5], old_state->__x[ 6], old_state->__x[ 7], old_state->__x[ 8], old_state->__x[ 9],
           old_state->__x[10], old_state->__x[11], old_state->__x[12], old_state->__x[13], old_state->__x[14], old_state->__x[15], old_state->__x[16], old_state->__x[17], old_state->__x[18], old_state->__x[19],
           old_state->__x[20], old_state->__x[21], old_state->__x[22], old_state->__x[23], old_state->__x[24], old_state->__x[25], old_state->__x[26], old_state->__x[27], old_state->__x[28],
           old_state->__fp, old_state->__lr, old_state->__pc, old_state->__sp, old_state->__cpsr);
}

kern_return_t catch_mach_exception_raise_state_identity (mach_port_t exception_port,
                                                         mach_port_t thread,
                                                         mach_port_t task,
                                                         exception_type_t exception,
                                                         mach_exception_data_t code,
                                                         mach_msg_type_number_t codeCnt,
                                                         int *flavor,
                                                         const thread_state_t old_state_,
                                                         mach_msg_type_number_t old_state_cnt,
                                                         thread_state_t new_state_,
                                                         mach_msg_type_number_t *new_state_cnt)
{
    if (*flavor != ARM_THREAD_STATE64) {
        return KERN_FAILURE;
    }

    const arm_thread_state64_internal *old_state = (const arm_thread_state64_internal *)old_state_;
    local_new_state = (arm_thread_state64_internal *)new_state_;
    memcpy(local_new_state, old_state, sizeof(arm_thread_state64_t));
    *new_state_cnt = old_state_cnt;

    static _Thread_local uint64_t pacFailedCount = 0;
    static _Thread_local uint64_t pacBruteForcedPtr = 0;
    static _Thread_local uint32_t lastDiversifier = 0;

    if (global_found) {
        return KERN_FAILURE;
    }

    if (current_thread_id == 0) {
        struct thread_info *tinfo = get_thread_info(exception_port);
        current_thread_id = tinfo->thread_id;
        local_sem_input_ready = tinfo->sem_input_ready;
        local_sem_output_ready = tinfo->sem_output_ready;
    }

    static _Thread_local int first_exception = 1;
    if (first_exception) {
        first_exception = 0;
        printf("got task port: %d\n", task);
        GlobalChildTaskPort = task;
        GlobalChildThreadPort = thread;
        signed_pointer = NSUserDefaults.standardUserDefaults.signedPointer;
        signed_diversifier = (uint32_t)NSUserDefaults.standardUserDefaults.signedDiversifier;
        if (signed_pointer != 0) {
            pacBruteForcedPtr = signed_pointer;
        }
        local_new_state->__lr = 0xFFFFFF00;
        local_new_state->__flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR;
        local_new_state->__flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR;
    }

    local_new_state->__flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC; // clear some flags
    
    uint64_t ptrL = (uint64_t)(code[1] & 0xFFFFFFFFF);
    uint64_t ptrR = (uint64_t)(brX8Address & 0xFFFFFFFFF);
    // code = {1, ptr} on iOS 16
    // code = {257, 0xFFFF...} on iOS 17
    if (exception == EXC_BAD_ACCESS && codeCnt == 2 &&
        (code[0] == 1 || code[0] == 257) &&
        (ptrL == ptrR || code[1] == 0xffffffffffffffff)) {
        uint32_t diversifier = old_state->__flags & 0xFF000000;
        if (signed_pointer == 0) {
            // each thread starts at different offset in 24 bits
            // t0: [0,1,2,3,...], t1: [4M,4M+1,4M+2,...], etc.

            static int total_threads = 1;
            if (total_threads == 1) {
                int mib[2] = {CTL_HW, HW_NCPU};
                int cpu_count = 1;
                size_t len = sizeof(cpu_count);
                sysctl(mib, 2, &cpu_count, &len, NULL, 0);
                total_threads = (cpu_count > 0 && cpu_count <= 8) ? cpu_count : 1;
            }

            uint64_t base_pac = ((uint64_t)brX8Address & 0xFFFFFFFFF);
            uint64_t search_space = 1ULL << 24; // 24-bit PAC space
            uint64_t thread_offset = (current_thread_id * (search_space / total_threads)) + pacFailedCount;
            uint64_t pac_value = thread_offset & (search_space - 1); // wraparound

            pacBruteForcedPtr = base_pac | ((pac_value << 39) & ~0x0080000000000000);
        } else if (signed_pointer == pacBruteForcedPtr) {
            pacBruteForcedPtr = signed_pointer;
        }
        lastDiversifier = diversifier;
        
        local_new_state->__pc = pacBruteForcedPtr;
        pacFailedCount++;
        if ((pacFailedCount & 0x3ffff) == 0) {
            printf("Still brute forcing PAC... total: %llu\n", pacFailedCount);
            printf("0x%016llx\n", pacBruteForcedPtr);
        }
        
        return KERN_SUCCESS;
    } else if (ptrL != ptrR) {
        //printf("Unexpected exception code for EXC_BAD_ACCESS: code[0]=%llu code[1]=0x%016llx (expected 0x%016lx)\n", code[0], code[1]&0xFFFFFFFFF, brX8Address&0xFFFFFFFFF);
    }
    
    //printf("exception handler raise state - exception %d\n", exception);
    static _Thread_local int exceptions_count = 0;
    if(pacBruteForcedPtr && exceptions_count > 0) {
        static int count = 0;
        if (count < 2) {
            count++;
            printf("PAC brute forced!\n");
            printf("- ptr: 0x%016llx\n", pacBruteForcedPtr);
            printf("- div: 0x%08x\n", lastDiversifier);

            atomic_store(&global_found, true);
            atomic_store(&global_result_ptr, pacBruteForcedPtr);
            atomic_store(&global_result_diversifier, lastDiversifier);

        }
        brX8Address = pacBruteForcedPtr;
        NSUserDefaults.standardUserDefaults.signedPointer = signed_pointer = pacBruteForcedPtr;
        NSUserDefaults.standardUserDefaults.signedDiversifier = lastDiversifier;
    }

    if (exceptions_count > 0) {
        sem_post(&local_sem_output_ready);
        if ((old_state->__lr & 0xFFFFFF00) != 0xFFFFFF00 || wantsDetach) {
            wantsDetach = NO;
            printf("Process might have crashed! unexpected lr value: 0x%llx\n", old_state->__lr);
            DumpRegisters(old_state);
            return KERN_FAILURE;
        }
    }

    __darwin_arm_thread_state64_set_pc_fptr(*local_new_state, ptrauth_sign_unauthenticated(ptrauth_strip((void *)brX8Address, ptrauth_key_function_pointer), ptrauth_key_function_pointer, 0));
    sem_wait(&local_sem_input_ready);

    exceptions_count++;
    return KERN_SUCCESS;
}

extern boolean_t mach_exc_server (mach_msg_header_t *msg, mach_msg_header_t *reply);

static void exception_server(mach_port_t exceptionPort, BOOL shouldExitOnException) {
    mach_msg_return_t rt;
    __Request__mach_exception_raise_state_identity_t msg;
    __Reply__mach_exception_raise_state_identity_t reply;
    BOOL handled = NO;

    do {
        rt = mach_msg((mach_msg_header_t *)&msg, MACH_RCV_MSG, 0, sizeof(union __RequestUnion__mach_exc_subsystem), exceptionPort, 0, MACH_PORT_NULL);
        assert(rt == MACH_MSG_SUCCESS);

        handled = mach_exc_server((mach_msg_header_t *)&msg, (mach_msg_header_t *)&reply);

        // Send the now-initialized reply
        rt = mach_msg((mach_msg_header_t *)&reply, MACH_SEND_MSG, reply.Head.msgh_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
        assert(rt == MACH_MSG_SUCCESS);
    } while (!shouldExitOnException || !handled);
}

static void* exception_server_thread_func(void* arg) {
    mach_port_t exceptionPort = (mach_port_t)arg;
    exception_server(exceptionPort, NO);
    return NULL;
}

mach_port_t setup_exception_server(void) {
    return setup_exception_server_with_id(0);
}

mach_port_t setup_exception_server_with_id(int thread_id) {
    struct thread_info *tinfo = &threads[num_threads];
    tinfo->thread_id = thread_id;
    sem_init(&tinfo->sem_input_ready, 0, 0);
    sem_init(&tinfo->sem_output_ready, 0, 0);
    tinfo->num_exceptions_handled = 0;

    // unauthenticated br x8 gadget
    void *handle = dlopen("/usr/lib/swift/libswiftDistributed.dylib", RTLD_GLOBAL);
    assert(handle != NULL);
    uint32_t *func = (uint32_t *)dlsym(RTLD_DEFAULT, "swift_distributed_execute_target");
    assert(func != NULL);
    for (; *func != 0xd61f0100; func++) {}
    brX8Address = (uint64_t)func;
    NSLog(@"Found br x8 at address: 0x%016lx\n", brX8Address);
    // if br x8 != saved address, clear saved address
    uint64_t savedPpointer = NSUserDefaults.standardUserDefaults.signedPointer;
    if (savedPpointer != 0 && (brX8Address&0xFFFFFFFFF) != (savedPpointer&0xFFFFFFFFF)) {
        NSLog(@"br x8 address changed, clearing saved signed pointer\n");
        NSUserDefaults.standardUserDefaults.signedPointer = 0;
        NSUserDefaults.standardUserDefaults.signedDiversifier = 0;
    }

    // PAC signing gadget
    func = (uint32_t *)zeroify_scalable_zone;
    for (; func[0] != 0xdac10230 || func[1] != 0xf9000110; func++) {}
    paciaAddress = (uint64_t)func;
    printf("Found pacia x16, x17 at address: 0x%016lx\n", paciaAddress);

    // change LR gadget
    func = (uint32_t *)dispatch_debug;
    for (; func[0] != 0xaa0103fe || func[1] != 0xf9402008; func++) {}
    changeLRAddress = (uint64_t)func;

    NSLog(@"exception server starting for thread %d\n", thread_id);
    mach_port_t server_port;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server_port);
    assert(kr == KERN_SUCCESS);
    kr = mach_port_insert_right(mach_task_self(), server_port, server_port, MACH_MSG_TYPE_MAKE_SEND);
    assert(kr == KERN_SUCCESS);

    char service_name[128];
    if (thread_id == 0) {
        snprintf(service_name, sizeof(service_name), "com.roothide.bootstrap.exception_server");
    } else {
        snprintf(service_name, sizeof(service_name), "com.roothide.bootstrap.exception_server.%d", thread_id);
    }
    kr = bootstrap_register(bootstrap_port, service_name, server_port);
    assert(kr == KERN_SUCCESS);
    NSLog(@"exception server %d registered on port 0x%x\n", thread_id, server_port);

    threads[num_threads].port = server_port;
    threads[num_threads].thread_id = thread_id;
    num_threads++;

    pthread_t exc_thread;
    pthread_create(&exc_thread, NULL, exception_server_thread_func, (void*)server_port);
    return server_port;
}

os_unfair_lock funcLock = OS_UNFAIR_LOCK_INIT;
void force_crash(void)
{
    local_new_state->__pc = brX8Address;
    local_new_state->__x[8] = 0x0;
    memset(&local_new_state->__x[0], 0, sizeof(local_new_state->__x));
    sem_post(&local_sem_input_ready);
    sem_wait(&local_sem_output_ready);
}
uint64_t RemoteArbCallInternal(char *name, uint64_t pc, uint64_t args[], int argCount) {
    // libswiftDistributed.dylib`swift_distributed_execute_target:
    // 0x20d1f0e58 <+352>: br     x8

    if (argCount > 8) {
        uint64_t sp = local_new_state->__sp; xpaci(sp);
        for (int i = 8; i < argCount; i++) {
            RemoteWrite64(sp + sizeof(uint64_t[i-8]), args[i]);
        }
        argCount = 8;
    }

    xpaci(pc);
    local_new_state->__x[8] = pc;
    memcpy(&local_new_state->__x[0], args, argCount * sizeof(uint64_t));

    printf("Calling function %s\n", name);
    sem_post(&local_sem_input_ready);
    sem_wait(&local_sem_output_ready);

    printf("- function returned x0=0x%llx\n", local_new_state->__x[0]);
    return local_new_state->__x[0];
}

uint64_t RemoteSignPACIA(uint64_t address, uint64_t modifier) {
    // libsystem_malloc.dylib`zeroify_scalable_zone:
    // 0x1b7102610 <+60>: pacia  x16, x17
    // 0x1b7102614 <+64>: str    x16, [x8, #0x10]
    // we're using br x8 to branch to here, and when it attempts to store to [x8],
    // it will crash and we can catch the exception to get the signed pointer
    local_new_state->__x[16] = address;
    local_new_state->__x[17] = modifier;
    RemoteArbCallInternal("pacia", paciaAddress, (uint64_t[]){}, 0);
    return local_new_state->__x[16];
}

void RemoteChangeLR(uint64_t newLR) {
    // libdispatch.dylib`__dispatch_event_loop_cancel_waiter.cold.1:
    // 0x18e527974 <+8>:  mov    x30, x1
    // libdispatch.dylib`__dispatch_event_loop_cancel_waiter.cold.2:
    // 0x18e527978 <+0>:  ldr    x8, [x0, #0x40]
    
    // x0=0 to cause a null deref to bring control back to us
    RemoteArbCallInternal("change_lr", changeLRAddress, (uint64_t[]){0, newLR}, 2);
}

uint32_t RemoteRead32(uint64_t address) {
    return (uint32_t)RemoteArbCall(__atomic_load_4, address, 3);
}
uint64_t RemoteRead64(uint64_t address) {
    return RemoteArbCall(__atomic_load_8, address, 3);
}

void RemoteWrite32(uint64_t address, uint32_t value) {
    RemoteArbCall(__atomic_store_4, address, value, 0);
}
void RemoteWrite64(uint64_t address, uint64_t value) {
    RemoteArbCall(__atomic_store_8, address, value, 0);
}

void RemoteWriteMemory(uint64_t address, const void *data, size_t length) {
    length = (length + 7) & ~7ULL;
    for (size_t offset = 0; offset < length; offset += 8) {
        RemoteWrite64(address + offset, *((uint64_t *)(data + offset)));
    }
}
// this might read overflow but idc for now
void RemoteWriteString(uint64_t address, const char *string) {
    size_t len = (strlen(string) + 7) & ~7ULL;
    RemoteWriteMemory(address, string, len);
}

void RemoteDetach(void) {
    // kill(SIGSTOP)
    // task_set_exception_ports
    wantsDetach = YES;
    mach_port_t task = (mach_port_t)RemoteArbCall(task_self_trap);
    RemoteArbCall(task_set_exception_ports, task, 2, 0, 1, 0);
}

kern_return_t
RemoteTaskRead64(uint64_t addr, mach_port_t task, uint64_t map) {
    kern_return_t kr = (kern_return_t)RemoteArbCall(vm_read_overwrite, task, addr, sizeof(uint64_t), map, map + 8);
    if (kr != KERN_SUCCESS) {
        printf("RemoteTaskRead64 failed\n");
        return kr;
    }
    return kr;
}

void RemoteTaskHexDump(uint64_t addr, size_t size, mach_port_t task, uint64_t map) {
    void *data = malloc(size);
    if (!data) return;

    size_t off = 0;
    while (off < size) {
        RemoteTaskRead64(addr + off, task, map);
        uint64_t v = RemoteRead64(map);

        size_t to_copy = (size - off) < 8 ? (size - off) : 8;
        memcpy((unsigned char*)data + off, &v, to_copy);
        off += to_copy;
    }

    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        if ((i % 16) == 0)
        {
            printf("[0x%016llx+0x%03zx] ", addr, i);
        }

        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    free(data);
}
