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

#include <Security/SecKey.h>
#include <Security/Security.h>
typedef struct CF_BRIDGED_TYPE(id) __SecCode const* SecStaticCodeRef; /* code on disk */
typedef enum { kSecCSDefaultFlags=0, kSecCSSigningInformation = 1 << 1 } SecCSFlags;
OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef* CF_RETURNS_RETAINED staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef* __nonnull CF_RETURNS_RETAINED information);

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
@property(nonatomic) mach_port_t exceptionPort;
@property(nonatomic) mach_port_t fakeBootstrapPort;
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
    // find launchd string offsets
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    if (!defaults.offsetLaunchdPath) {
        NSDictionary *offsets = getLaunchdStringOffsets();
        defaults.offsetLaunchdPath = [offsets[@"/sbin/launchd"] unsignedLongValue];
        // AMFI is only needed for iOS 17.0 to bypass launch constraint
        defaults.offsetAMFI = [offsets[@"AMFI"] unsignedLongValue];
        NSLog(@"Found launchd path string offset: 0x%lx\n", defaults.offsetLaunchdPath);
        if (defaults.offsetAMFI) {
            NSLog(@"Found AMFI string offset: 0x%lx\n", defaults.offsetAMFI);
        }
    }
    
    self.exceptionPort = setup_exception_server();
    self.fakeBootstrapPort = setup_fake_bootstrap_server();

}
void testButtonTapped() {
  launchTest(@"dtsecurity");
  NSLog(@"launch dtsecurity");
}
void arbCallButtonTapped() {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{

        kern_return_t kr;
        
        // Create a region which holds temp data (should we use stack instead?)
        vm_size_t page_size = getpagesize();
        vm_address_t map = RemoteArbCall(mmap, 0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (!map) {
            NSLog(@"Failed to call mmap. Please try resetting pointer and try again\n");
            return;
        }
        NSLog(@"Mapped memory at 0x%lx\n", map);
        
        // Test mkdir
//        RemoteWriteString(map, "/tmp/.it_works");
//        RemoteArbCall(mkdir, map, 0700);
        
        // Get my task port
        mach_port_t dtsecurity_task = (mach_port_t)RemoteArbCall(task_self_trap);
//        kr = (kern_return_t)RemoteArbCall(task_for_pid, dtsecurity_task, getpid(), map);
//        if (kr != KERN_SUCCESS) {
//            NSLog(@"Failed to get my task port\n");
//            return;
//        }
//        mach_port_t my_task = (mach_port_t)RemoteRead32(map);
        // Map the page we allocated in dtsecurity to this process
//        kr = (kern_return_t)RemoteArbCall(vm_remap, my_task, map, page_size, 0, VM_FLAGS_ANYWHERE, dtsecurity_task, map, false, map+8, map+12, VM_INHERIT_SHARE);
//        if (kr != KERN_SUCCESS) {
//            NSLog(@"Failed to create dtsecurity<->haxx shared mapping\n");
//            return;
//        }
//        vm_address_t local_map = RemoteRead64(map);
//        NSLog(@"Created shared mapping: 0x%lx\n", local_map);
//        NSLog(@"read: 0x%llx\n", *(uint64_t *)local_map);
        
        // Get dtsecurity dyld base for blr x19
        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
         kr = (kern_return_t)RemoteArbCall(task_info, dtsecurity_task, TASK_DYLD_INFO, map + 8, map);
        if (kr != KERN_SUCCESS) {
            NSLog(@"task_info failed\n");
            return;
        }
        struct dyld_all_image_infos *remote_dyld_all_image_infos_addr = (void *)(RemoteRead64(map + 8) + offsetof(struct task_dyld_info, all_image_info_addr));
        vm_address_t remote_dyld_base;
        do {
            remote_dyld_base = RemoteRead64((uint64_t)&remote_dyld_all_image_infos_addr->dyldImageLoadAddress);
            // FIXME: why do I have to sleep a bit for dyld base to be available?
            usleep(100000);
        } while (remote_dyld_base == 0);
        NSLog(@"dtsecurity dyld base: 0x%lx\n", remote_dyld_base);
        
        // Get launchd task port
        kr = (kern_return_t)RemoteArbCall(task_for_pid, dtsecurity_task, 1, map);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Failed to get launchd task port\n");
            return;
        }
        
        mach_port_t launchd_task = (mach_port_t)RemoteRead32(map);
        NSLog(@"Got launchd task port: %d\n", launchd_task);
        
        // Get remote dyld base
        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
        kr = (kern_return_t)RemoteArbCall(task_info, launchd_task, TASK_DYLD_INFO, map + 8, map);
        if (kr != KERN_SUCCESS) {
            NSLog(@"task_info failed\n");
            return;
        }
        remote_dyld_all_image_infos_addr = (void *)(RemoteRead64(map + 8) + offsetof(struct task_dyld_info, all_image_info_addr));
        NSLog(@"launchd dyld_all_image_infos_addr: %p\n", remote_dyld_all_image_infos_addr);
        
        // uint32_t infoArrayCount = &remote_dyld_all_image_infos_addr->infoArrayCount;
        kr = (kern_return_t)RemoteArbCall(vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArrayCount, sizeof(uint32_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            NSLog(@"vm_read_overwrite _dyld_all_image_infos->infoArrayCount failed\n");
            return;
        }
        uint32_t infoArrayCount = RemoteRead32(map);
        NSLog(@"launchd infoArrayCount: %u\n", infoArrayCount);
        
        //const struct dyld_image_info* infoArray = &remote_dyld_all_image_infos_addr->infoArray;
        kr = (kern_return_t)RemoteArbCall(vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArray, sizeof(uint64_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            NSLog(@"vm_read_overwrite _dyld_all_image_infos->infoArray failed\n");
            return;
        }
        
        // Enumerate images to find launchd base
        vm_address_t launchd_base = 0;
        vm_address_t infoArray = RemoteRead64(map);
        for (int i = 0; i < infoArrayCount; i++) {
            kr = (kern_return_t)RemoteArbCall(vm_read_overwrite, launchd_task, infoArray + sizeof(uint64_t[i*3]), sizeof(uint64_t), map, map + 8);
            uint64_t base = RemoteRead64(map);
            if (base % page_size) {
                // skip unaligned entries, as they are likely in dsc
                continue;
            }
            NSLog(@"Image[%d] = 0x%llx\n", i, base);
            // read magic, cputype, cpusubtype, filetype
            kr = (kern_return_t)RemoteArbCall(vm_read_overwrite, launchd_task, base, 16, map, map + 16);
            uint64_t magic = RemoteRead32(map);
            if (magic != MH_MAGIC_64) {
                NSLog(@"not a mach-o (magic: 0x%x)\n", (uint32_t)magic);
                continue;
            }
            uint32_t filetype = RemoteRead32(map + 12);
            if (filetype == MH_EXECUTE) {
                NSLog(@"found launchd executable at 0x%llx\n", base);
                launchd_base = base;
                break;
            }
        }
        
        // Reprotect rw
        // minimum page = 0x5f000;
        vm_offset_t launchd_str_off = NSUserDefaults.standardUserDefaults.offsetLaunchdPath;
        vm_offset_t amfi_str_off = NSUserDefaults.standardUserDefaults.offsetAMFI;
        
        NSLog(@"reprotecting 0x%lx\n", launchd_base + 0x5f000);
        RemoteChangeLR(0xFFFFFF00); // fix autibsp
        kr = (kern_return_t)RemoteArbCall(vm_protect, launchd_task, (launchd_base + 0x5f000), 0x4000*4, false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) {
            NSLog(@"vm_protect failed: kr = %s\n", mach_error_string(kr));
            sleep(5);
            return;
        }

        // https://github.com/wh1te4ever/TaskPortHaxxApp/commit/327022fe73089f366dcf1d0d75012e6288916b29
        // Bypass panic by launch constraints
        // Method 2: Patch `AMFI` string that being used as _amfi_launch_constraint_set_spawnattr's arguments

        // Patch string `AMFI`
        
        const char *newStr = "AAAA\x00";
        RemoteWriteString(map, newStr);
        RemoteChangeLR(0xFFFFFF00); // fix autibsp
        kr = (kern_return_t)RemoteArbCall(vm_write, launchd_task, launchd_base + amfi_str_off, map, 5);
        if (kr != KERN_SUCCESS) {
            NSLog(@"vm_write failed\n");
            sleep(5);
            return;
        }
        RemoteTaskHexDump(launchd_base + amfi_str_off, 0x100, launchd_task, (uint64_t)map);

        // Overwrite /sbin/launchd string to /var/.launchd
        const char *newPath = getLaunchdPath().UTF8String;
        RemoteWriteString(map, newPath);
        RemoteChangeLR(0xFFFFFF00); // fix autibsp
        kr = (kern_return_t)RemoteArbCall(vm_write, launchd_task, launchd_base + launchd_str_off, map, strlen(newPath));
        if (kr != KERN_SUCCESS) {
            NSLog(@"vm_write failed\n");
            sleep(5);
            return;
        }
        NSLog(@"Successfully overwrote launchd executable path string to %s\n", newPath);

        RemoteArbCall(exit, 0);
        
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
