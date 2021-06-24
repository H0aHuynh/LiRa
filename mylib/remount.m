//
//  remount.c
//  LiRa jailbreak
//
//  Created by HoaHuynh on 2021/02/12.
//

#include "remount.h"
#include "kapi.h"
#include "utils.h"
#include "k_offsets.h"
#include "k_utils.h"
#include "amfi.h"
#include <string.h>
#include <sys/attr.h>
#include <sys/snapshot.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>
#include <malloc/_malloc.h>
#include <errno.h>
#include <IOKit/IOKitLib.h>
#import <Foundation/Foundation.h>

static char* mntpathSW;
static char* mntpath;

bool remount(uint64_t launchd_proc) {
    mntpathSW = "/var/MobileSoftwareUpdate/rootfsmnt";
    mntpath = strdup("/var/MobileSoftwareUpdate/rootfsmnt");
    uint64_t rootvnode = findRootVnode(launchd_proc);
    util_info("rootvnode: 0x%llx", rootvnode);
    
    if(isRenameRequired()) {
        if(access(mntpathSW, F_OK) == 0) {
            [[NSFileManager defaultManager] removeItemAtPath:[NSString stringWithUTF8String:mntpathSW] error:nil];
        }
        
        mkdir(mntpath, 0755);
        chown(mntpath, 0, 0);
        
        if(isOTAMounted()) {
            util_error("OTA update already mounted");
            return false;
        }
        
        uint64_t kernCreds = kapi_read64(kproc_find_by_pid(0) + OFFSET(proc, p_ucred));
        uint64_t selfCreds = kapi_read64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred));
        
        kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), kernCreds);
        grabEntitlementsForRootFS(kproc_find_by_pid(getpid()));
        sleep(1);
        
        char* bootSnapshot = find_boot_snapshot();
        if(!bootSnapshot
           || mountRealRootfs(rootvnode)) {
            resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
            kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
            return false;
        }
        
        int fd = open("/var/MobileSoftwareUpdate/rootfsmnt", O_RDONLY, 0);
        if(fd <= 0
           || fs_snapshot_revert(fd, bootSnapshot, 0) != 0) {
            util_error("fs_snapshot_revert failed");
            resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
            kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
            return false;
        }
        close(fd);
                
        unmount(mntpath, MNT_FORCE);
        
        if(mountRealRootfs(rootvnode)) {
            resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
            kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
            return false;
        }
        
        uint64_t newmnt = findNewMount(rootvnode);
        if(!newmnt) {
            resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
            kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
            return false;
        }
        
        if(!unsetSnapshotFlag(newmnt)) {
            resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
            kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
            return false;
        }
        
        int fd2 = open("/var/MobileSoftwareUpdate/rootfsmnt", O_RDONLY, 0);
        if(fd <= 0
           || fs_snapshot_rename(fd2, bootSnapshot, "orig-fs", 0) != 0) {
            util_error("fs_snapshot_rename failed");
            resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
            kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
            return false;
        }
        close(fd2);
        
        unmount(mntpath, 0);
        [[NSFileManager defaultManager] removeItemAtPath:[NSString stringWithUTF8String:mntpath] error:nil];
        
        resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
        kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
        
        util_info("Successfully remounted RootFS! Reboot after 5 sec.");
        sleep(5);
        reboot(0);
    } else {
        uint64_t vmount = kapi_read64(rootvnode + OFFSET(vnode, v_mount));
        uint32_t vflag = kapi_read32(vmount + OFFSET(mount, mnt_flag)) & ~(MNT_RDONLY);
        kapi_write32(vmount + OFFSET(mount, mnt_flag), vflag & ~(MNT_ROOTFS));
        
        char* dev_path = strdup("/dev/disk0s1s1");
        int retval = mount("apfs", "/", MNT_UPDATE, &dev_path);
        free(dev_path);
        
        kapi_write32(vmount + OFFSET(mount, mnt_flag), vflag | (MNT_NOSUID));
        if(retval == 0) {
            util_info("Already remounted RootFS!");
            return true;
        }
        return false;
    }
    return true;
}

uint64_t findRootVnode(uint64_t launchd_proc) {
    //  https://github.com/apple/darwin-xnu/blob/xnu-7195.60.75/bsd/sys/proc_internal.h#L193
    //  https://github.com/apple/darwin-xnu/blob/xnu-7195.60.75/bsd/sys/vnode_internal.h#L127
    
    uint64_t textvp = kapi_read64(launchd_proc + OFFSET(proc, textvp));
    uint64_t nameptr = kapi_read64(textvp + OFFSET(vnode, v_name));
    char name[20];
    kapi_read(nameptr, &name, 20);  //  <- launchd;
    
    uint64_t sbin = kapi_read64(textvp + OFFSET(vnode, v_parent));
    nameptr = kapi_read64(sbin + OFFSET(vnode, v_name));
    kapi_read(nameptr, &name, 20);  //  <- sbin
    
    uint64_t rootvnode = kapi_read64(sbin + OFFSET(vnode, v_parent));
    nameptr = kapi_read64(sbin + OFFSET(vnode, v_name));
    kapi_read(nameptr, &name, 20);  //  <- / (ROOT)
    
    uint32_t flags = kapi_read32(rootvnode + OFFSET(vnode, v_flag));
    util_info("rootvnode flags: 0x%x", flags);
    
    return rootvnode;
}

bool isRenameRequired() {
    struct statfs *st;
    
    int ret = getmntinfo(&st, MNT_NOWAIT);
    if(ret <= 0) {
        util_error("getmntinfo error");
    }
    
    for (int i = 0; i < ret; i++) {
        if(strstr(st[i].f_mntfromname, "com.apple.os.update-") != NULL) {
            return true;
        }
        if(strcmp(st[i].f_mntfromname, "/dev/disk0s1s1") == 0) {
            return false;
        }
    }
    return false;
}

bool isOTAMounted() {
    const char* path = strdup("/var/MobileSoftwareUpdate/mnt1");
    
    struct stat buffer;
    if (lstat(path, &buffer) != 0) {
        return false;
    }
    
    if((buffer.st_mode & S_IFMT) != S_IFDIR) {
        return false;
    }
    
    char* cwd = getcwd(nil, 0);
    chdir(path);
    
    struct stat p_buf;
    lstat("..", &p_buf);
    
    if(cwd) {
        chdir(cwd);
        free(cwd);
    }
    
    return buffer.st_dev != p_buf.st_dev || buffer.st_ino == p_buf.st_ino;
}

char* find_boot_snapshot() {
    io_registry_entry_t chosen = IORegistryEntryFromPath(0, "IODeviceTree:/chosen");
    CFDataRef data = IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    if(!data)
        return nil;
    IOObjectRelease(chosen);
    
    CFIndex length = CFDataGetLength(data) * 2 + 1;
    char *manifestHash = (char*)calloc(length, sizeof(char));
    
    int i = 0;
    for (i = 0; i<(int)CFDataGetLength(data); i++) {
        sprintf(manifestHash+i*2, "%02X", CFDataGetBytePtr(data)[i]);
    }
    manifestHash[i*2] = 0;
    
    CFRelease(data);

    char* systemSnapshot = malloc(sizeof(char) * 64);
    strcpy(systemSnapshot, "com.apple.os.update-");
    strcat(systemSnapshot, manifestHash);
    
    return systemSnapshot;
}

int mountRealRootfs(uint64_t rootvnode) {
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/vnode_internal.h#L127
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/mount_internal.h#L107
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/miscfs/specfs/specdev.h#L77
    uint64_t vmount = kapi_read64(rootvnode + OFFSET(vnode, v_mount));
    uint64_t dev = kapi_read64(vmount + OFFSET(mount, mnt_devvp));
    
    uint64_t nameptr = kapi_read64(dev + OFFSET(vnode, v_name));
    char name[20];
    kapi_read(nameptr, &name, 20);   //  <- disk0s1s1
    util_info("Found dev vnode name: %s", name);
    
    uint64_t specinfo = kapi_read64(dev + OFFSET(vnode, vu_specinfo));
    uint32_t flags = kapi_read32(specinfo + OFFSET(specinfo, si_flags));
    util_info("Found dev flags: 0x%x", flags);
    
    kapi_write32(specinfo + OFFSET(specinfo, si_flags), 0);
    char* fspec = strdup("/dev/disk0s1s1");
    
    struct hfs_mount_args mntargs;
    mntargs.fspec = fspec;
    mntargs.hfs_mask = 1;
    gettimeofday(nil, &mntargs.hfs_timezone);

    int retval = mount("apfs", mntpath, 0, &mntargs);
    free(fspec);
    
    util_info("Mount completed with status: %d", retval);
    if(retval == -1) {
        util_info("Mount failed with errno: %d", errno);
    }
    
    return retval;
}

uint64_t findNewMount(uint64_t rootvnode) {
    uint64_t vmount = kapi_read64(rootvnode + OFFSET(vnode, v_mount));
    
    vmount = kapi_read64(vmount + OFFSET(mount, mnt_next));
    while (vmount != 0) {
        uint64_t dev = kapi_read64(vmount + OFFSET(mount, mnt_devvp));
        if(dev != 0) {
            uint64_t nameptr = kapi_read64(dev + OFFSET(vnode, v_name));
            char name[20];
            kapi_read(nameptr, &name, 20);
            char* devName = name;
            util_info("Found dev vnode name: %s", devName);
            
            if(strcmp(devName, "disk0s1s1") == 0) {
                return vmount;
            }
        }
        vmount = kapi_read64(vmount + OFFSET(mount, mnt_next));
    }
    return 0;
}

bool unsetSnapshotFlag(uint64_t newmnt) {
    //  https://github.com/apple/darwin-xnu/blob/main/bsd/sys/mount_internal.h#L107
    uint64_t dev = kapi_read64(newmnt + OFFSET(mount, mnt_devvp));
    uint64_t nameptr = kapi_read64(dev + OFFSET(vnode, v_name));
    char name[20];
    kapi_read(nameptr, &name, 20);
    util_info("Found dev vnode name: %s", name);
    
    uint64_t specinfo = kapi_read64(dev + OFFSET(vnode, vu_specinfo));
    uint64_t flags = kapi_read32(specinfo + OFFSET(specinfo, si_flags));
    util_info("Found dev flags: 0x%llx", flags);
    
    uint64_t vnodelist = kapi_read64(newmnt + OFFSET(mount, mnt_vnodelist));
    while (vnodelist != 0) {
        util_info("vnodelist: 0x%llx", vnodelist);
        uint64_t nameptr = kapi_read64(vnodelist + OFFSET(vnode, v_name));
        unsigned long len = kstrlen(nameptr);
        char name[len];
        kapi_read(nameptr, &name, len);
        
        char* vnodeName = name;
        util_info("Found vnode name: %s", vnodeName);
        
        if(strstr(vnodeName, "com.apple.os.update-") != NULL) {
            uint64_t vdata = kapi_read64(vnodelist + OFFSET(vnode, v_data));
            uint32_t flag = kapi_read32(vdata + OFFSET(apfs, data_flag));
            util_info("Found APFS flag: 0x%x", flag);
            
            if ((flag & 0x40) != 0) {
                util_info("would unset the flag here to: 0x%x", flag & ~0x40);
                kapi_write32(vdata + OFFSET(apfs, data_flag), flag & ~0x40);
                return true;
            }
        }
        usleep(1000);
        vnodelist = kapi_read64(vnodelist + 0x20);
    }
    return false;
}

unsigned long kstrlen(uint64_t string) {
    if (!string) return 0;
    
    unsigned long len = 0;
    char ch = 0;
    int i = 0;
    while (true) {
        kapi_read(string + i, &ch, 1);
        if (!ch) break;
        len++;
        i++;
    }
    return len;
}

bool restore_rootfs() {
    if(!isRenameRequired()) {
        char* bootSnapshot = find_boot_snapshot();
        if(!bootSnapshot)
            return false;
        
        remove("/var/cache");
        remove("/var/lib");
        
        uint64_t kernCreds = kapi_read64(kproc_find_by_pid(0) + OFFSET(proc, p_ucred));
        uint64_t selfCreds = kapi_read64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred));
        
        kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), kernCreds);
        grabEntitlementsForRootFS(kproc_find_by_pid(getpid()));
        sleep(1);
        
        int fd = open("/", O_RDONLY, 0);
        if(fd <= 0
           || fs_snapshot_rename(fd, "orig-fs", bootSnapshot, 0) != 0) {
            util_error("fs_snapshot_rename failed");
            resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
            kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
            return false;
        }
        
        if(fs_snapshot_revert(fd, bootSnapshot, 0) != 0) {
            util_error("fs_snapshot_revert failed");
            resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
            kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
            return false;
        }
        close(fd);
        
        resetEntitlementsForRootFS(kproc_find_by_pid(getpid()));
        kapi_write64(kproc_find_by_pid(getpid()) + OFFSET(proc, p_ucred), selfCreds);
        util_info("Successfully restored RootFS! Reboot after 5 sec.");
        sleep(5);
        reboot(0);
    } else {
        util_error("RootFS Restore Not Required");
        return false;
    }
    return true;
}
