#import <objc/runtime.h>
#import "AppDelegate.h"


static void (*orig_NSLog)(NSString *format, va_list ap);

static void hooked_NSLog(NSString *format, va_list ap)
{
    char *utf8 = NULL;
    if (vasprintf(&utf8, format.UTF8String, ap) >= 0) {
        NSString *line = [NSString stringWithUTF8String:utf8];
        free(utf8);

        if (orig_NSLog) orig_NSLog(format, ap);

        dispatch_async(dispatch_get_main_queue(), ^{
            [AppDelegate addLogText:line];
        });
    }
}

__attribute__((constructor))
static void install_NSLog_hook(void)
{
    Method m = class_getClassMethod(objc_getMetaClass("NSLog"), @selector(log));
    orig_NSLog = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)hooked_NSLog);
}


__attribute__((constructor))
static void redirect_stdio(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    static int pfd[2];
    pipe(pfd);
    dup2(pfd[1], fileno(stdout));
    dup2(pfd[1], fileno(stderr));

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        char buf[2048];
        ssize_t n;
        while ((n = read(pfd[0], buf, sizeof(buf)-1)) > 0) {
            buf[n] = 0;
            NSString *line = [NSString stringWithUTF8String:buf];
            dispatch_async(dispatch_get_main_queue(), ^{
                [AppDelegate addLogText:line];
            });
        }
    });
}
