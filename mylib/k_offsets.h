//
//  k_offsets.h
//  ios-fuzzer
//
//  Created by Quote on 2021/1/26.
//  Copyright © 2021 Quote. All rights reserved.
//

#ifndef k_offsets_h
#define k_offsets_h

#define TF_PLATFORM (0x00000400)
#define CS_PLATFORM_BINARY (0x04000000)
#define CS_INSTALLER (0x00000008)
#define CS_GET_TASK_ALLOW (0x00000004)
#define CS_RESTRICT (0x00000800)
#define CS_HARD (0x00000100)
#define CS_KILL (0x00000200)

// Generate the name for an offset.
#define OFFSET(base_, object_)      _##base_##__##object_##__offset_

// Generate the name for the size of an object.
#define SIZE(object_)               _##object_##__size_

#ifdef Q_INTERNAL
#define qexternal
#else
#define qexternal extern
#endif

// Parameters for ipc_entry.
qexternal size_t SIZE(ipc_entry);
qexternal size_t OFFSET(ipc_entry, ie_object);

// Parameters for ipc_port.
qexternal size_t OFFSET(ipc_port, ip_bits);
qexternal size_t OFFSET(ipc_port, ip_references);
qexternal size_t OFFSET(ipc_port, ip_kobject);

// Parameters for struct ipc_space.
qexternal size_t OFFSET(ipc_space, is_table_size);
qexternal size_t OFFSET(ipc_space, is_table);

// Parameters for struct task.
qexternal size_t OFFSET(task, map);
qexternal size_t OFFSET(task, itk_space);
qexternal size_t OFFSET(task, bsd_info);
qexternal size_t OFFSET(task, t_flags);

qexternal size_t OFFSET(proc, le_next);
qexternal size_t OFFSET(proc, le_prev);
qexternal size_t OFFSET(proc, task);
qexternal size_t OFFSET(proc, p_ucred);
qexternal size_t OFFSET(proc, p_pid);
qexternal size_t OFFSET(proc, p_fd);
qexternal size_t OFFSET(proc, textvp);
qexternal size_t OFFSET(proc, p_csflags);
qexternal size_t OFFSET(proc, p_name);

qexternal size_t OFFSET(vnode, v_name);
qexternal size_t OFFSET(vnode, v_parent);
qexternal size_t OFFSET(vnode, v_flag);
qexternal size_t OFFSET(vnode, v_mount);
qexternal size_t OFFSET(vnode, vu_specinfo);
qexternal size_t OFFSET(vnode, v_data);

qexternal size_t OFFSET(mount, mnt_devvp);
qexternal size_t OFFSET(mount, mnt_next);
qexternal size_t OFFSET(mount, mnt_vnodelist);
qexternal size_t OFFSET(mount, mnt_flag);

qexternal size_t OFFSET(specinfo, si_flags);

qexternal size_t OFFSET(apfs, data_flag);

qexternal size_t OFFSET(filedesc, fd_ofiles);
qexternal size_t OFFSET(fileproc, fp_glob);
qexternal size_t OFFSET(fileglob, fg_data);
qexternal size_t OFFSET(pipe, buffer);

qexternal size_t OFFSET(ucred, cr_posix);
qexternal size_t OFFSET(ucred, cr_label);

qexternal size_t OFFSET(amfi, slot_off);

qexternal size_t SIZE(posix_cred);

// Parameters for OSDictionary.
qexternal size_t OFFSET(OSDictionary, count);
qexternal size_t OFFSET(OSDictionary, capacity);
qexternal size_t OFFSET(OSDictionary, dictionary);

// Parameters for OSString.
qexternal size_t OFFSET(OSString, string);

// Parameters for IOSurfaceRootUserClient.
qexternal size_t OFFSET(IOSurfaceRootUserClient, surfaceClients);

qexternal kptr_t kc_kernel_base;
qexternal kptr_t kc_kernel_map;
qexternal kptr_t kc_kernel_task;
qexternal kptr_t kc_IOSurfaceClient_vt;
qexternal kptr_t kc_IOSurfaceClient_vt_0;

#undef qexternal

void kernel_offsets_init(void);

#endif /* k_offsets_h */
