#import <sys/syslog.h>
#import "AppDelegate.h"

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
