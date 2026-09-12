#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <errno.h>
#import <fcntl.h>
#import <libgen.h>
#import <stdarg.h>
#import <stdio.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>

static NSString *DMBundle(void) {
    return NSBundle.mainBundle.bundleIdentifier ?: @"unknown";
}

static NSDictionary *DMPreferences(void) {
    NSDictionary *d = [[NSUserDefaults standardUserDefaults] persistentDomainForName:@"com.shosh.detectionmonitor"];
    return d ?: @{};
}

static BOOL DMEnabled(void) {
    NSNumber *n = DMPreferences()[@"Enabled"];
    return n ? n.boolValue : YES;
}

static BOOL DMTargetMatches(void) {
    NSString *target = DMPreferences()[@"TargetBundle"];
    return target.length == 0 || [target isEqualToString:DMBundle()];
}

static BOOL DMSuspicious(NSString *value) {
    if (value.length == 0) return NO;
    static NSArray *needles;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[@"/var/jb", @"/var/binpack", @"/var/mobile/Library/Preferences", @"/Applications/Cydia.app", @"/Applications/Sileo.app", @"/Applications/Zebra.app", @"/usr/lib/substrate", @"/Library/MobileSubstrate", @"/bootstrap", @"/palera1n", @"/dopamine", @"/ellekit", @"frida", @"ssh"]; 
    });
    NSString *lower = value.lowercaseString;
    for (NSString *needle in needles) if ([lower containsString:needle.lowercaseString]) return YES;
    return NO;
}

static void DMWrite(NSString *api, NSString *argument, NSString *result, int savedErrno) {
    if (!DMEnabled() || !DMTargetMatches()) return;
    NSDictionary *p = DMPreferences();
    BOOL all = [p[@"LogAllPaths"] boolValue];
    if (!all && !DMSuspicious(argument)) return;

    NSString *dir = @"/var/mobile/Library/Logs/DetectionMonitor";
    NSFileManager *fm = NSFileManager.defaultManager;
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *path = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.log", DMBundle()]];
    NSDateFormatter *f = [NSDateFormatter new];
    f.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"[%@] bundle=%@ api=%@ arg=%@ result=%@ errno=%d suspicious=%@\n", f.stringFromDate:NSDate.date, DMBundle(), api, argument ?: @"", result ?: @"", savedErrno, DMSuspicious(argument) ? @"YES" : @"NO"];
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!h) { [line writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil]; return; }
    [h seekToEndOfFile]; [h writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [h closeFile];
}

%hookf(int, access, const char *path, int mode) {
    int r = %orig(path, mode); int e = errno;
    DMWrite(@"access", path ? @(path) : @"(null)", [NSString stringWithFormat:@"%d", r], e);
    return r;
}

%hookf(int, stat, const char *path, struct stat *sb) {
    int r = %orig(path, sb); int e = errno;
    DMWrite(@"stat", path ? @(path) : @"(null)", [NSString stringWithFormat:@"%d", r], e);
    return r;
}

%hookf(int, lstat, const char *path, struct stat *sb) {
    int r = %orig(path, sb); int e = errno;
    DMWrite(@"lstat", path ? @(path) : @"(null)", [NSString stringWithFormat:@"%d", r], e);
    return r;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    FILE *r = %orig(path, mode); int e = errno;
    DMWrite(@"fopen", path ? @(path) : @"(null)", r ? @"non-null" : @"NULL", e);
    return r;
}

%hookf(void *, dlopen, const char *path, int mode) {
    void *r = %orig(path, mode); int e = errno;
    DMWrite(@"dlopen", path ? @(path) : @"(null)", r ? @"non-null" : @"NULL", e);
    return r;
}

%hookf(pid_t, fork) {
    pid_t r = %orig; int e = errno;
    DMWrite(@"fork", @"(no argument)", [NSString stringWithFormat:@"%d", r], e);
    return r;
}

%ctor {
    @autoreleasepool {
        NSLog(@"[DetectionMonitor] loaded for %@", DMBundle());
    }
}
