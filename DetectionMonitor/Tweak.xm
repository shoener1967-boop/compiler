#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <stdio.h>
#import <sys/stat.h>
#import <unistd.h>

static __thread BOOL dmIsLogging = NO;

static NSString *DMBundle(void) {
    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier;
    return bundleID.length > 0 ? bundleID : @"unknown";
}

static NSDictionary *DMPreferences(void) {
    NSDictionary *preferences =
        [[NSUserDefaults standardUserDefaults]
            persistentDomainForName:@"com.shosh.detectionmonitor"];

    return preferences ?: @{};
}

static BOOL DMEnabled(void) {
    NSNumber *enabled = DMPreferences()[@"Enabled"];
    return enabled ? enabled.boolValue : YES;
}

static BOOL DMTargetMatches(void) {
    NSString *target = DMPreferences()[@"TargetBundle"];

    // Leeres Target bedeutet: alle injizierten Apps überwachen.
    return target.length == 0 || [target isEqualToString:DMBundle()];
}

static NSString *DMStringFromCString(const char *value) {
    if (value == NULL) {
        return @"(null)";
    }

    NSString *result = [NSString stringWithUTF8String:value];
    return result ?: @"(invalid-utf8)";
}

static BOOL DMSuspicious(NSString *value) {
    if (value.length == 0) {
        return NO;
    }

    static NSArray<NSString *> *needles;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        needles = @[
            @"/var/jb",
            @"/var/binpack",
            @"/var/mobile/library/preferences",
            @"/applications/cydia.app",
            @"/applications/sileo.app",
            @"/applications/zebra.app",
            @"/usr/lib/substrate",
            @"/library/mobilesubstrate",
            @"/bootstrap",
            @"/palera1n",
            @"/dopamine",
            @"/ellekit",
            @"frida",
            @"ssh"
        ];
    });

    NSString *lowercaseValue = value.lowercaseString;

    for (NSString *needle in needles) {
        if ([lowercaseValue containsString:needle]) {
            return YES;
        }
    }

    return NO;
}

static void DMWrite(
    NSString *api,
    NSString *argument,
    NSString *result,
    int savedErrno
) {
    if (dmIsLogging) {
        return;
    }

    if (!DMEnabled() || !DMTargetMatches()) {
        return;
    }

    NSDictionary *preferences = DMPreferences();
    BOOL logAllPaths = [preferences[@"LogAllPaths"] boolValue];

    if (!logAllPaths && !DMSuspicious(argument)) {
        return;
    }

    dmIsLogging = YES;

    @autoreleasepool {
        NSString *directory =
            @"/var/mobile/Library/Logs/DetectionMonitor";

        NSFileManager *fileManager = [NSFileManager defaultManager];

        [fileManager createDirectoryAtPath:directory
               withIntermediateDirectories:YES
                                attributes:nil
                                     error:nil];

        NSString *filename =
            [NSString stringWithFormat:@"%@.log", DMBundle()];

        NSString *logPath =
            [directory stringByAppendingPathComponent:filename];

        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";

        NSString *timestamp =
            [formatter stringFromDate:[NSDate date]];

        NSString *line =
            [NSString stringWithFormat:
                @"[%@] bundle=%@ api=%@ arg=%@ result=%@ errno=%d suspicious=%@\n",
                timestamp,
                DMBundle(),
                api ?: @"unknown",
                argument ?: @"",
                result ?: @"",
                savedErrno,
                DMSuspicious(argument) ? @"YES" : @"NO"];

        NSFileHandle *handle =
            [NSFileHandle fileHandleForWritingAtPath:logPath];

        if (handle == nil) {
            [line writeToFile:logPath
                   atomically:YES
                     encoding:NSUTF8StringEncoding
                        error:nil];
        } else {
            [handle seekToEndOfFile];

            NSData *data =
                [line dataUsingEncoding:NSUTF8StringEncoding];

            [handle writeData:data];
            [handle closeFile];
        }
    }

    dmIsLogging = NO;
}

%hookf(int, access, const char *path, int mode) {
    int result = %orig(path, mode);
    int savedErrno = errno;

    DMWrite(
        @"access",
        DMStringFromCString(path),
        [NSString stringWithFormat:@"%d", result],
        savedErrno
    );

    errno = savedErrno;
    return result;
}

%hookf(int, stat, const char *path, struct stat *buffer) {
    int result = %orig(path, buffer);
    int savedErrno = errno;

    DMWrite(
        @"stat",
        DMStringFromCString(path),
        [NSString stringWithFormat:@"%d", result],
        savedErrno
    );

    errno = savedErrno;
    return result;
}

%hookf(int, lstat, const char *path, struct stat *buffer) {
    int result = %orig(path, buffer);
    int savedErrno = errno;

    DMWrite(
        @"lstat",
        DMStringFromCString(path),
        [NSString stringWithFormat:@"%d", result],
        savedErrno
    );

    errno = savedErrno;
    return result;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    FILE *result = %orig(path, mode);
    int savedErrno = errno;

    DMWrite(
        @"fopen",
        DMStringFromCString(path),
        result != NULL ? @"non-null" : @"NULL",
        savedErrno
    );

    errno = savedErrno;
    return result;
}

%hookf(void *, dlopen, const char *path, int mode) {
    void *result = %orig(path, mode);
    int savedErrno = errno;

    DMWrite(
        @"dlopen",
        DMStringFromCString(path),
        result != NULL ? @"non-null" : @"NULL",
        savedErrno
    );

    errno = savedErrno;
    return result;
}

%hookf(pid_t, fork) {
    pid_t result = %orig;
    int savedErrno = errno;

    DMWrite(
        @"fork",
        @"(no argument)",
        [NSString stringWithFormat:@"%d", result],
        savedErrno
    );

    errno = savedErrno;
    return result;
}

%ctor {
    @autoreleasepool {
        NSLog(
            @"[DetectionMonitor] loaded for %@",
            DMBundle()
        );
    }
}
