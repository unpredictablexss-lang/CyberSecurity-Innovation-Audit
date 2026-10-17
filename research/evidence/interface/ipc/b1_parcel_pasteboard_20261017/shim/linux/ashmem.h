/*
 * UAPI definitions for the ashmem driver.
 *
 * The host kernel has no ashmem driver, so the header is not installed. The
 * ioctl numbers below are the ones from the upstream kernel header
 * (include/uapi/linux/ashmem.h, GPL-2.0 WITH Linux-syscall-note) and are
 * reproduced only so that the real c_utils ashmem.cpp compiles unchanged.
 * AshmemGetSize therefore is the real cutils function: on a descriptor that is
 * not ashmem the ioctl fails and it returns -1, which is the property the
 * fixed pasteboard revision relies on and the vulnerable one does not check.
 */
#ifndef STUB_LINUX_ASHMEM_H
#define STUB_LINUX_ASHMEM_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define __ASHMEMIOC 0x77

#define ASHMEM_NAME_LEN 256
#define ASHMEM_NAME_DEF "dev/ashmem"

struct ashmem_pin {
    __u32 offset;
    __u32 len;
};

#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_GET_NAME _IOR(__ASHMEMIOC, 2, char[ASHMEM_NAME_LEN])
#define ASHMEM_SET_SIZE _IOW(__ASHMEMIOC, 3, size_t)
#define ASHMEM_GET_SIZE _IO(__ASHMEMIOC, 4)
#define ASHMEM_SET_PROT_MASK _IOW(__ASHMEMIOC, 5, unsigned long)
#define ASHMEM_GET_PROT_MASK _IO(__ASHMEMIOC, 6)
#define ASHMEM_PIN _IOW(__ASHMEMIOC, 7, struct ashmem_pin)
#define ASHMEM_UNPIN _IOW(__ASHMEMIOC, 8, struct ashmem_pin)
#define ASHMEM_GET_PIN_STATUS _IO(__ASHMEMIOC, 9)
#define ASHMEM_PURGE_ALL_CACHES _IO(__ASHMEMIOC, 10)

#endif
