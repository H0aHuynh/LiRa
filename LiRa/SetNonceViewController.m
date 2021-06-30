//
//  ViewController.m
//  pre-jailbreak
//
//  Created by Quote on 2021/2/19.
//

#include <sys/mount.h>
#include <mach/mach.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#import <SafariServices/SafariServices.h>

#import "SetNonceViewController.h"
#include "../mylib/mycommon.h"
#include "newpatch.h"
#import "MobileGestalt.h"
#include "iokit.h"
#define VERSION @"1.0"
#define PROFILE1 "/var/mobile/Library/Preferences/com.apple.MobileAsset.plist"
#define IS_PAD ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad)
#define IS_PAD ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad

static SetNonceViewController *sharedController = nil;

kern_return_t set_generator(const char *new_generator);
const char *get_generator(void);
struct iboot64_img iboot_in;

uint64_t iodtnvram_obj = 0x0;
uint64_t original_vtab = 0x0;

kern_return_t set_generator(const char *new_generator) {
    kern_return_t ret = KERN_SUCCESS;

    const char *current_generator = get_generator();
    NSLog(@"got current generator: %s", current_generator);

    if (current_generator != NULL) {
        if (strcmp(current_generator, new_generator) == 0) {
            NSLog(@"not setting new generator -- generator is already set");
            free((void *)current_generator);
            return KERN_SUCCESS;
        }
        free((void *)current_generator);
    }

    CFStringRef str = CFStringCreateWithCStringNoCopy(NULL, new_generator, kCFStringEncodingUTF8, kCFAllocatorNull);
    if (str == NULL) {
        NSLog(@"failed to allocate new CFStringRef");
        return KERN_FAILURE;
    }

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, 0, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (dict == NULL) {
        NSLog(@"failed to allocate new CFMutableDictionaryRef");
        return KERN_FAILURE;
    }

    CFDictionarySetValue(dict, CFSTR("com.apple.System.boot-nonce"), str);
    CFRelease(str);

    io_service_t nvram = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    if (!MACH_PORT_VALID(nvram)) {
        NSLog(@"failed to open IODTNVRAM service");
        return KERN_FAILURE;
    }

    ret = IORegistryEntrySetCFProperties(nvram, dict);

    return ret;
}

const char *get_generator() {
    kern_return_t ret = KERN_SUCCESS;

    io_service_t nvram = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    if (!MACH_PORT_VALID(nvram)) {
        NSLog(@"failed to open IODTNVRAM service");
        return NULL;
    }

    io_string_t buffer;
    unsigned int len = 256;
    ret = IORegistryEntryGetProperty(nvram, "com.apple.System.boot-nonce", buffer, &len);
    if (ret != KERN_SUCCESS) {
        // Nonce is not set
        NSLog(@"nonce is not currently set");
        return NULL;
    }

    return strdup(buffer);
}

@interface SetNonceViewController ()
@property (weak, nonatomic) IBOutlet UILabel *system;
@property (weak, nonatomic) IBOutlet UILabel *nonce;
@property (weak, nonatomic) IBOutlet UITextField *textField;
@property (nonatomic, copy) NSString *valueStr;
@property (weak, nonatomic) IBOutlet UIButton *button;

@end

@interface UIDeviceHardware : NSObject
- (NSString *)platform;
@end

@implementation UIDeviceHardware
- (NSString *)platform {
    size_t size;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    char *machine = malloc(size);
    sysctlbyname("hw.machine", machine, &size, NULL, 0);
    NSString *platform = [NSString stringWithUTF8String:machine];
    free(machine);
    return platform;
}
@end

static CFStringRef (*$MGCopyAnswer)(CFStringRef);

bool vaildGenerator(NSString *generator) {
    if ([generator length] != 18 || [generator characterAtIndex:0] != '0' || [generator characterAtIndex:1] != 'x') {
        return false;
    }
    for (int i = 2; i <= 17; i++) {
        if (!isxdigit([generator characterAtIndex:i])) {
            return false;
        }
    }
    return true;
}


@implementation SetNonceViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.button.layer.cornerRadius = 15;
    self.button.backgroundColor = UIColor.blueColor;
    // Do any additional setup after loading the view.
    // System info
    NSString *systemStr = [NSString stringWithFormat:@"%@ %@ %@ - %@",[[UIDeviceHardware alloc] platform],[[UIDevice currentDevice] systemName],[[UIDevice currentDevice] systemVersion],VERSION];


    void *gestalt = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_GLOBAL | RTLD_LAZY);
    $MGCopyAnswer = dlsym(gestalt, "MGCopyAnswer");

    // System Info
    self.system.text = systemStr;

    if (self.view.tag == 143) {
        self.textField.delegate = self;

        uint32_t uid = getuid();
        printf("getuid() returns %u\n", uid);
        printf("whoami: %s\n", uid == 0 ? "root" : "mobile");
        NSString *whoami = [NSString stringWithUTF8String:((void)(@"%s"), uid == 0 ? "root" : "mobile")];
        if ([whoami isEqualToString:@"mobile"]) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Bạn không thể đặt Nonce"
                                                                           message:[@"Trạng thái:" stringByAppendingString:whoami]
                                                                    preferredStyle:UIAlertControllerStyleAlert];

            [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                      style:UIAlertActionStyleDefault
                                                    handler:^(UIAlertAction *action) {}]];

            [self presentViewController:alert animated:YES completion:nil];
        }
        // Nonce Info
    self.nonce.text = [self getGenerator];
}
}
- (IBAction)textChanged:(UITextField *)textfield {
    CGFloat maxLength = 18;
    NSString *toBeString = textfield.text;

    UITextRange *selectedRange = [textfield markedTextRange];
    UITextPosition *position = [textfield positionFromPosition:selectedRange.start offset:0];
    if (!position || !selectedRange) {
        if (toBeString.length > maxLength) {
            NSRange rangeIndex = [toBeString rangeOfComposedCharacterSequenceAtIndex:maxLength];
            if (rangeIndex.length == 1) {
                textfield.text = [toBeString substringToIndex:maxLength];
            } else {
                NSRange rangeRange = [toBeString rangeOfComposedCharacterSequencesForRange:NSMakeRange(0, maxLength)];
                textfield.text = [toBeString substringWithRange:rangeRange];
            }
        }
    }
    NSLog(@"textfield data:%@",textfield.text);
    self.valueStr = textfield.text;
}

- (NSString *)getGenerator {
    uint32_t gid = getgid();
   printf("getgid() returns %u\n", gid);
    uint32_t uid = getuid();
    printf("getuid() returns %u\n", uid);

    if (uid != 0 && gid != 0) return @"Tình trạng: Chưa root";

    NSString *generator = nil;

    if (get_generator()) {
        generator = [NSString stringWithCString:get_generator() encoding:NSUTF8StringEncoding];
    }

    return generator ? [NSString stringWithFormat:@"Nonce: %@", generator] : @"Nonce: Không đặt Nonce";
}

- (void)setValue {
    NSString *value = nil;
    if (!self.valueStr || [self.valueStr isEqualToString:@""]) {
        value = @"0x1111111111111111";
    } else {
        value = self.valueStr;
    }

    self.valueStr = value;

    [self.view endEditing:YES];

    if (!vaildGenerator(value)) {
        UIAlertController *alertController =
        [UIAlertController alertControllerWithTitle:@"Wrong Value"
                                            message:[NSString stringWithFormat:@"\"%@\"\nLỗi định dạng!", value]
                                     preferredStyle:UIAlertControllerStyleAlert];

        [alertController addAction:[UIAlertAction actionWithTitle:@"OK"
                                                            style:UIAlertActionStyleDefault
                                                          handler:^(UIAlertAction *action) {}]];

        [self presentViewController:alertController animated:YES completion:nil];
        // return
        return;
    } else {
        UIAlertController *alertController =
        [UIAlertController alertControllerWithTitle:@"Đặt Generator"
                                            message:value
                                     preferredStyle:UIAlertControllerStyleAlert];

        [alertController addAction:[UIAlertAction actionWithTitle:@"OK"
                                                            style:UIAlertActionStyleDefault
                                                          handler:^(UIAlertAction *action) {
            [self setgenerator];
        }]];

        [self presentViewController:alertController animated:YES completion:nil];
    }
}

- (void)setgenerator {
    if (getuid() != 0) {
        setuid(0);
    }

    if (getuid() != 0) {
        UIAlertController *alertController =
        [UIAlertController alertControllerWithTitle:@"Bạn không thể đặt nonce"
                                            message:@"Trạng thái: mobile"
                                     preferredStyle:UIAlertControllerStyleAlert];

        [alertController addAction:[UIAlertAction actionWithTitle:@"OK"
                                                            style:UIAlertActionStyleDefault
                                                          handler:^(UIAlertAction *action) {}]];

        [self presentViewController:alertController animated:YES completion:nil];
        // return
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unlock_nvram(&iboot_in);

        char *setnonce = (char *)[self.valueStr UTF8String];

        set_generator(setnonce);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            // Nonce Info change
            self.nonce.text = [self getGenerator];
        });
    });
}

- (BOOL)textFieldShouldReturn:(UITextField*)textField {
    [self setValue];
    return YES;
}


- (IBAction)setGenerator:(UIButton *)sender {
    [self setValue];
}

- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(nullable UIEvent *)event {
    [super touchesEnded:touches withEvent:event];
    [self becomeFirstResponder];
}

- (BOOL)canBecomeFirstResponder {
    return YES;
}



@end





