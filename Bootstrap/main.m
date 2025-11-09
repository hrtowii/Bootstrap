#import "AppDelegate.h"
#include "NSUserDefaults+appDefaults.h"
#include "common.h"
#include "taskporthaxx.h"
#import <UIKit/UIKit.h>

#import <IOKit/IOKitLib.h>
int main(int argc, char *argv[]) {
#if !DTSECURITY_WAIT_FOR_DEBUGGER
  char *startSuspended = getenv("HAXX_START_SUSPENDED");
  if (startSuspended && atoi(startSuspended)) {
    usleep(100000); // FIXME: how to sleep until ptrace attach?
  }
#endif

  if (argc >= 2) {
    @try {
      SYSLOG("Bootstrap cmd %s", argv[1]);
      ASSERT(getuid() == 0);

      if (strcmp(argv[1], "bootstrap") == 0) {
        int bootstrap();
        exit(bootstrap());
      } else if (strcmp(argv[1], "unbootstrap") == 0) {
        int unbootstrap();
        exit(unbootstrap());
      } else if (strcmp(argv[1], "enableapp") == 0) {
        int enableForApp(NSString * bundlePath);
        exit(enableForApp(@(argv[2])));
      } else if (strcmp(argv[1], "disableapp") == 0) {
        int disableForApp(NSString * bundlePath);
        exit(disableForApp(@(argv[2])));
      } else if (strcmp(argv[1], "rebuildiconcache") == 0) {
        int rebuildIconCache();
        exit(rebuildIconCache());
      } else if (strcmp(argv[1], "reboot") == 0) {
        sync();
        sleep(1);
        reboot(0);
        sleep(5);
        exit(-1);
      } else if (strcmp(argv[1], "dtsecurity") == 0) {
        NSString *execDir = @"/var/db/com.apple.xpc.roleaccountd.staging/exec";
        [NSFileManager.defaultManager createDirectoryAtPath:execDir
                                withIntermediateDirectories:YES
                                                 attributes:nil
                                                      error:nil];
        NSString *outDir =
            @"/var/db/com.apple.xpc.roleaccountd.staging/exec/TaskPortHaxx.xpc";
        if (![[NSFileManager defaultManager] fileExistsAtPath:outDir]) {
          NSError *error = nil;
          [NSFileManager.defaultManager
              copyItemAtPath:@"/System/Library/PrivateFrameworks/"
                             @"DVTInstrumentsFoundation.framework/XPCServices/"
                             @"com.apple.dt.instruments.dtsecurity.xpc"
                      toPath:outDir
                       error:&error];
          if (error) {
            NSLog(@"Failed to copy dtsecurity.xpc: %@", error);
            return 1;
          }
        }
        char *portName = getenv("HAXX_EXCEPTION_PORT_NAME");
        char *path = "/var/db/com.apple.xpc.roleaccountd.staging/exec/"
                     "TaskPortHaxx.xpc/com.apple.dt.instruments.dtsecurity";
        return child_execve(portName, path);
      } else if (strcmp(argv[1], "updatebrain") == 0) {
        char *portName = getenv("HAXX_EXCEPTION_PORT_NAME");
        char *path = "/var/db/com.apple.xpc.roleaccountd.staging/exec/"
                     "com.apple.MobileSoftwareUpdate.UpdateBrainService.xpc/"
                     "com.apple.MobileSoftwareUpdate.UpdateBrainService";
        return child_execve(portName, path);
      } else if (strcmp(argv[1], "updatebrain-prepare") == 0) {
        return child_stage1_prepare();
      } else if (strcmp(argv[1], "testprefs") == 0) {
        SYSLOG("locale=%@", [NSUserDefaults.appDefaults valueForKey:@"locale"]);
        [NSUserDefaults.appDefaults setValue:@"CA" forKey:@"locale"];
        [NSUserDefaults.appDefaults synchronize];
        SYSLOG("locale=%@", [NSUserDefaults.appDefaults valueForKey:@"locale"]);
        exit(0);
      } else {
        SYSLOG("unknown cmd: %s", argv[1]);
        ABORT();
      }
    } @catch (NSException *exception) {
      STRAPLOG("***exception: %@", exception);
      exit(-1);
    }
  }

  NSString *appDelegateClassName;
  @autoreleasepool {
    // Setup code that might create autoreleased objects goes here.
    appDelegateClassName = NSStringFromClass([AppDelegate class]);
  }
  return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
