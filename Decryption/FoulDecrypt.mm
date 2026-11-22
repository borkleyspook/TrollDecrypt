//
//  FoulDecrypt.mm
//  TrollDecrypt
//
//  Port of fouldecrypt15's main.cpp into TrollDecrypt.
//
//  Original project: https://github.com/.../fouldecrypt15
//  The encryption logic itself is unchanged from the original implementation:
//    - map the encrypted file read-only and the output file read/write
//    - for each Mach-O slice, find LC_ENCRYPTION_INFO[_64]
//    - call the private mremap_encrypted() syscall on the encrypted pages
//    - when cryptoff is not 16K aligned, patch the apple_protect_pager for the
//      mapped VM entry via kerninfra (kernel R/W) so the syscall works on a
//      page that is aligned to the hardware 16K page size
//    - write the decrypted bytes into the output and zero out cryptid
//
//  Differences from the original CLI tool:
//    - logging goes through NSLog instead of printf
//    - kernel init failure returns an error instead of exit(1), so the caller
//      can fall back to TrollDecrypt's existing task_for_pid decryption method
//    - thin/fat handling guards against out-of-bounds slices
//

#import "FoulDecrypt.h"

// shared.h (force-included via OBJCFLAGS) redefines NSLog. With -fno-modules,
// Foundation is included textually, so the macro would mangle Foundation's own
// NSLog declaration. Undefine it here, then import Foundation normally.
// FDLOG below provides its own [FoulDecrypt] prefix, so nothing is lost.
#undef NSLog
#import <Foundation/Foundation.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach.h>

#include <exception>
#include <stdexcept>

// kerninfra sits at TrollDecrypt/kerninfra. Use a relative include so no
// extra header search paths are required in the Makefile.
#include "../kerninfra/kerninfra.hpp"

#undef PAGE_SIZE
#define TD_FD_PAGE_SIZE       0x4000
#define TD_FD_EXEC_PAGE_SIZE  0x1000

// Set to NO to silence the verbose FoulDecrypt trace messages.
static BOOL td_fd_verbose = YES;
#define FDLOG(fmt, ...) \
    do { if (td_fd_verbose) NSLog(@"[FoulDecrypt] " fmt, ##__VA_ARGS__); } while (0)

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

// NOTE: No "prime by executing the binary" step is needed. The old port tried
// posix_spawn() to initialise the FairPlay pager, but that fails with ENOEXEC
// for apps TrollDecrypt cannot launch. mremap_encrypted() has no privilege
// check and does not require the app to have been executed: fairplayd locates
// the license purely by the SC_Info/*.sinf file next to the input binary. See
// the mode-based attempt code in td_fd_unprotect() below.

// ---------------------------------------------------------------------------
// File mapping helper (ported from main.cpp's map()).
// ---------------------------------------------------------------------------
static uint8_t *td_fd_map(const char *path, bool mutableMap, size_t *size, int *descriptor) {
    int f = open(path, mutableMap ? (O_CREAT | O_TRUNC | O_RDWR) : O_RDONLY, 0755);
    if (f < 0) {
        FDLOG(@"open(%s) failed: %s", path, strerror(errno));
        return NULL;
    }

    if (mutableMap && ftruncate(f, *size) < 0) {
        FDLOG(@"ftruncate(%s) failed: %s", path, strerror(errno));
        close(f);
        return NULL;
    }

    struct stat st;
    if (fstat(f, &st) < 0) {
        FDLOG(@"fstat(%s) failed: %s", path, strerror(errno));
        close(f);
        return NULL;
    }

    uint8_t *base = (uint8_t *)mmap(NULL, st.st_size,
                                    mutableMap ? (PROT_READ | PROT_WRITE) : PROT_READ,
                                    mutableMap ? MAP_SHARED : MAP_PRIVATE, f, 0);
    if (base == MAP_FAILED) {
        FDLOG(@"mmap(%s) failed: %s", path, strerror(errno));
        close(f);
        return NULL;
    }

    *size = (size_t)st.st_size;
    if (descriptor) {
        *descriptor = f;
    } else {
        close(f);
    }
    return base;
}

// ---------------------------------------------------------------------------
// Kernel backend (ported from main.cpp's prepare_kernel()).
// ---------------------------------------------------------------------------
static bool td_fd_kernelReady = false;

static int td_fd_prepareKernel(void) {
    if (!td_fd_kernelReady) {
        int ret = init_kerninfra(KERNLOG_NONE);
        if (ret) {
            FDLOG(@"init_kerninfra failed with status %d", ret);
            return ret;
        }
        td_fd_kernelReady = true;
        FDLOG(@"kerninfra initialized");
    }
    return 0;
}

BOOL TDFoulDecryptKernelAvailable(void) {
    return td_fd_prepareKernel() == 0;
}

// ---------------------------------------------------------------------------
// Private syscall used by both FoulDecrypt and FlexDecrypt.
// ---------------------------------------------------------------------------
extern "C" int mremap_encrypted(void *, size_t, uint32_t, uint32_t, uint32_t);

static void *td_fd_mmap(void *base, size_t size, int prot, int flags, int fd, size_t off) {
    void *ret = mmap(base, size, prot, flags, fd, off);
    if (ret == MAP_FAILED) {
        FDLOG(@"mmap(base=%p size=0x%zx off=0x%zx) failed: %s", base, size, off, strerror(errno));
    }
    return ret;
}

static int td_fd_mremapEncrypted(void *base, size_t cryptsize, uint32_t cryptid,
                                 uint32_t cpuType, uint32_t cpuSubType) {
    int ret = mremap_encrypted(base, cryptsize, cryptid, cpuType, cpuSubType);
    if (ret) {
        FDLOG(@"mremap_encrypted(%p, 0x%zx) failed: %d (%s)", base, cryptsize, ret, strerror(errno));
    }
    return ret;
}

// ---------------------------------------------------------------------------
// One FairPlay attempt.
//
// cryptid=2 (CRYPTID_MODEL_ENCRYPTION) is the crucial detail: inside
// vm_map_apple_protected, cryptid only selects a code path, and value 2 skips
// the requirement that the mapping be PROT_EXEC. That means a plain
// mmap(PROT_READ) is enough and AMFI library validation is never involved.
// The old port always used cryptid=1 + PROT_READ|PROT_EXEC, which is exactly
// what dyld does and what produces EPERM when the app cannot be launched.
//
// mremap_encrypted itself has no privilege check (no special entitlements),
// and fairplayd finds the licence by the SC_Info/*.sinf file next to the
// input path — so no priming exec is necessary.
// ---------------------------------------------------------------------------
static int td_fd_attemptDecrypt(int f, size_t sliceOff, uint32_t cryptoff, uint32_t cryptsize,
                                uint32_t csOff, uint32_t csSize,
                                uint32_t cryptid, bool useExec, bool addSigs,
                                uint32_t cpuType, uint32_t cpuSubType,
                                uint8_t *outBuf, const uint8_t *origBuf) {
    size_t mapLen = ((size_t)cryptoff + cryptsize + TD_FD_PAGE_SIZE - 1) & ~(TD_FD_PAGE_SIZE - 1);
    int prot = PROT_READ | (useExec ? PROT_EXEC : 0);
    void *base = td_fd_mmap(NULL, mapLen, prot, MAP_PRIVATE, f, sliceOff);
    if (base == MAP_FAILED) return -1;

#ifdef F_ADDFILESIGS_RETURN
    if (addSigs && csSize) {
        struct fsignatures fs = {0};
        fs.fs_file_start = (off_t)sliceOff;
        fs.fs_blob_start = (void *)(uintptr_t)csOff;
        fs.fs_blob_size = csSize;
        if (fcntl(f, F_ADDFILESIGS_RETURN, &fs) == -1) {
            FDLOG(@"F_ADDFILESIGS_RETURN failed: %s (continuing)", strerror(errno));
        }
    }
#else
    (void)addSigs; (void)csOff; (void)csSize;
#endif

    uint8_t *cryptBase = (uint8_t *)base + cryptoff;
    errno = 0;
    int ret = mremap_encrypted(cryptBase, cryptsize, cryptid, cpuType, cpuSubType);
    if (ret != 0) {
        FDLOG(@"mode(cryptid=%u exec=%d sigs=%d): mremap_encrypted failed: %d (%s)",
              cryptid, useExec ? 1 : 0, addSigs ? 1 : 0, ret, strerror(errno));
        munmap(base, mapLen);
        return -1;
    }

    // Read the decrypted pages with vm_read_overwrite so a page-in failure is
    // reported as a kern_return_t instead of raising SIGBUS.
    size_t pages = (cryptsize + TD_FD_PAGE_SIZE - 1) / TD_FD_PAGE_SIZE;
    for (size_t i = 0; i < pages; i++) {
        size_t off = i * TD_FD_PAGE_SIZE;
        size_t n = MIN(TD_FD_PAGE_SIZE, (size_t)cryptsize - off);
        vm_size_t got = 0;
        kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                             (vm_address_t)(cryptBase + off), (vm_size_t)n,
                                             (vm_address_t)(outBuf + off), &got);
        if (kr != KERN_SUCCESS || got != n) {
            FDLOG(@"mode(cryptid=%u exec=%d sigs=%d): vm_read_overwrite page %zu failed: kr=%d",
                  cryptid, useExec ? 1 : 0, addSigs ? 1 : 0, i, kr);
            munmap(base, mapLen);
            return -1;
        }
    }

    if (memcmp(outBuf, origBuf, cryptsize) == 0) {
        FDLOG(@"mode(cryptid=%u exec=%d sigs=%d): pages unchanged; not decrypted",
              cryptid, useExec ? 1 : 0, addSigs ? 1 : 0);
        munmap(base, mapLen);
        return -1;
    }

    FDLOG(@"mode(cryptid=%u exec=%d sigs=%d): SUCCESS", cryptid, useExec ? 1 : 0, addSigs ? 1 : 0);
    munmap(base, mapLen);
    return 0;
}

// ---------------------------------------------------------------------------
// Decrypt one encrypted region of a Mach-O slice (ported from unprotect()).
// ---------------------------------------------------------------------------
static int td_fd_unprotect(int f, uint8_t *inputData, uint8_t *dupe, int cpuType, int cpuSubType,
                           struct encryption_info_command *info, size_t machoOff,
                           uint32_t csOff, uint32_t csSize) {
    // mremap_encrypted requires the input address to be 4K aligned.
    if ((info->cryptoff & (TD_FD_EXEC_PAGE_SIZE - 1)) != 0) {
        FDLOG(@"cryptoff 0x%x is not 4K aligned; cannot decrypt", info->cryptoff);
        return 1;
    }
    if (info->cryptsize == 0) {
        FDLOG(@"empty encryption range");
        return 1;
    }

    FDLOG(@"decrypting: off=0x%x size=0x%x cryptid=%u cpu=0x%x sub=0x%x",
          info->cryptoff, info->cryptsize, info->cryptid, cpuType, cpuSubType);

    size_t offAligned = info->cryptoff & ~(TD_FD_PAGE_SIZE - 1);
    uint8_t *decryptedBuf = (uint8_t *)malloc(info->cryptsize);
    if (!decryptedBuf) {
        FDLOG(@"malloc(%u) failed", info->cryptsize);
        return 1;
    }
    const uint8_t *origBuf = inputData + info->cryptoff;

    if ((info->cryptoff & (TD_FD_PAGE_SIZE - 1)) == 0) {
        // 16K-aligned: try the modern cryptid=2 (PROT_READ-only) path first.
        // The cryptid=1/PROT_EXEC "what dyld does" modes are kept as fallbacks.
        struct {
            uint32_t cryptid;
            bool useExec;
            bool addSigs;
        } modes[] = {
            { 2, false, false },
#ifdef F_ADDFILESIGS_RETURN
            { 2, false, true  },
#endif
            { 1, true,  false },
#ifdef F_ADDFILESIGS_RETURN
            { 1, true,  true  },
#endif
        };
        bool ok = false;
        for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
            if (td_fd_attemptDecrypt(f, machoOff, info->cryptoff, info->cryptsize,
                                     csOff, csSize,
                                     modes[i].cryptid, modes[i].useExec, modes[i].addSigs,
                                     (uint32_t)cpuType, (uint32_t)cpuSubType,
                                     decryptedBuf, origBuf) == 0) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            free(decryptedBuf);
            return 1;
        }
    } else {
        // Slow path: cryptoff is only 4K aligned. Patch the pager backing the
        // 16K-aligned mapping so mremap_encrypted decrypts from the right bytes.
        // Use cryptid=2 + PROT_READ so the VM layer does not require PROT_EXEC.
        FDLOG(@"cryptoff is NOT 16K aligned; using kerninfra pager patch");
        if (td_fd_prepareKernel()) {
            FDLOG(@"kerninfra unavailable; cannot decrypt unaligned cryptoff");
            free(decryptedBuf);
            return 1;
        }

        for (size_t off = offAligned;
             off < (size_t)info->cryptoff + info->cryptsize;
             off += TD_FD_PAGE_SIZE) {
            size_t offEnd = MIN(off + TD_FD_PAGE_SIZE,
                                (size_t)info->cryptoff + info->cryptsize);
            size_t curMapLen = (offEnd - off) & (TD_FD_PAGE_SIZE - 1);
            if (!curMapLen) curMapLen = TD_FD_PAGE_SIZE;

            size_t inPageStart = off < (size_t)info->cryptoff
                               ? (size_t)info->cryptoff - off : 0;
            size_t cryptOff = off + inPageStart;

            char *cryptbase = (char *)td_fd_mmap(NULL, curMapLen, PROT_READ,
                                                 MAP_PRIVATE, f, off + machoOff);
            if (cryptbase == MAP_FAILED) {
                free(decryptedBuf);
                return 1;
            }

            if (td_fd_mremapEncrypted(cryptbase, curMapLen, 2, cpuType, cpuSubType)) {
                munmap(cryptbase, curMapLen);
                free(decryptedBuf);
                return 1;
            }

            // Locate the VM entry for the mapping and redirect the
            // apple_protect_pager to the exact encrypted bytes we want.
            try {
                auto curProc = proc_t_p(current_proc());
                addr_t encVmEntryAddr = lookup_vm_map_entry(curProc.task()._map().load_addr(),
                                                            (addr_t)cryptbase);
                if (!encVmEntryAddr) {
                    FDLOG(@"lookup_vm_map_entry failed for %p", cryptbase);
                    munmap(cryptbase, curMapLen);
                    free(decryptedBuf);
                    return 1;
                }
                auto encVmEntry = _vm_map_entry_p(encVmEntryAddr);
                auto vmobj = encVmEntry.vme_object();
                auto applePager = apple_protect_pager_t_p(vmobj.shadow().pager().load_addr());
                applePager.crypto_backing_offset().store(machoOff + cryptOff);
                applePager.crypto_start().store(inPageStart);
                FDLOG(@"patched pager: backing=0x%llx start=0x%zx",
                      (unsigned long long)(machoOff + cryptOff), inPageStart);
            } catch (const std::exception &e) {
                FDLOG(@"kerninfra exception: %s", e.what());
                munmap(cryptbase, curMapLen);
                free(decryptedBuf);
                return 1;
            } catch (...) {
                FDLOG(@"unknown kerninfra exception");
                munmap(cryptbase, curMapLen);
                free(decryptedBuf);
                return 1;
            }

            memmove((char *)decryptedBuf + cryptOff - info->cryptoff,
                    cryptbase + inPageStart, curMapLen - inPageStart);
            munmap(cryptbase, curMapLen);
        }
    }

    memcpy(dupe + info->cryptoff, decryptedBuf, info->cryptsize);
    free(decryptedBuf);
    return 0;
}

// ---------------------------------------------------------------------------
// Decrypt a single (thin) Mach-O slice (ported from decrypt_macho_slide()).
// ---------------------------------------------------------------------------
static int td_fd_decryptMachoSlice(int f, uint8_t *inputData, uint8_t *outputData, size_t machoOff) {
    uint32_t offset = 0;
    int cpuType = 0, cpuSubType = 0, ncmds = 0;
    uint32_t magic = *(uint32_t *)inputData;

    if (magic == MH_MAGIC_64) {
        struct mach_header_64 *header = (struct mach_header_64 *)inputData;
        cpuType = header->cputype;
        cpuSubType = header->cpusubtype;
        ncmds = header->ncmds;
        offset = sizeof(struct mach_header_64);
    } else if (magic == MH_MAGIC) {
        struct mach_header *header = (struct mach_header *)inputData;
        cpuType = header->cputype;
        cpuSubType = header->cpusubtype;
        ncmds = header->ncmds;
        offset = sizeof(struct mach_header);
    } else {
        FDLOG(@"unknown Mach-O magic 0x%x at slice offset 0x%zx", magic, machoOff);
        return 1;
    }

    struct encryption_info_command *encryptionInfo = NULL;
    uint32_t csOff = 0, csSize = 0;
    uint32_t cmdOffset = offset;
    for (uint32_t i = 0; i < (uint32_t)ncmds; i++) {
        struct load_command *command = (struct load_command *)(inputData + cmdOffset);
        if (command->cmd == LC_ENCRYPTION_INFO || command->cmd == LC_ENCRYPTION_INFO_64) {
            encryptionInfo = (struct encryption_info_command *)command;
            offset = cmdOffset;  // keep offset pointing at LC_ENCRYPTION_INFO for the output patch
        } else if (command->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *lc = (struct linkedit_data_command *)command;
            csOff = lc->dataoff;
            csSize = lc->datasize;
        }
        cmdOffset += command->cmdsize;
    }

    if (!encryptionInfo || !encryptionInfo->cryptid) {
        FDLOG(@"slice at 0x%zx is not encrypted", machoOff);
        return 0;
    }

    if (td_fd_unprotect(f, inputData, outputData, cpuType, cpuSubType, encryptionInfo,
                        machoOff, csOff, csSize) != 0) {
        FDLOG(@"failed to decrypt slice at 0x%zx", machoOff);
        return 1;
    }

    // Tell dyld the pages are already decrypted.
    struct encryption_info_command *outEncryptionInfo =
        (struct encryption_info_command *)(outputData + offset);
    outEncryptionInfo->cryptid = 0;
    FDLOG(@"slice at 0x%zx decrypted", machoOff);
    return 0;
}

// ---------------------------------------------------------------------------
// Decrypt a whole Mach-O file (thin or fat) (ported from decrypt_macho()).
// ---------------------------------------------------------------------------
static int td_fd_decryptMachO(const char *inputFile, const char *outputFile) {
    // fairplayd locates the licence via <bundle>/SC_Info/<name>.sinf next to the
    // input binary. Log its presence so a remaining EPERM is easy to interpret.
    NSString *inPath = [NSString stringWithUTF8String:inputFile];
    NSString *sinfPath = [[inPath stringByDeletingLastPathComponent]
        stringByAppendingPathComponent:
            [NSString stringWithFormat:@"SC_Info/%@.sinf", [inPath lastPathComponent]]];
    FDLOG(@"licence: %@ (exists=%d)", sinfPath,
          [[NSFileManager defaultManager] fileExistsAtPath:sinfPath] ? 1 : 0);

    FDLOG(@"mapping input: %s", inputFile);
    size_t baseSize = 0;
    int f = -1;
    uint8_t *base = td_fd_map(inputFile, false, &baseSize, &f);
    if (!base) return 1;
    if (baseSize < sizeof(uint32_t)) {
        FDLOG(@"input file is too small");
        munmap(base, baseSize);
        close(f);
        return 1;
    }

    FDLOG(@"mapping output: %s", outputFile);
    size_t dupeSize = baseSize;
    uint8_t *dupe = td_fd_map(outputFile, true, &dupeSize, NULL);
    if (!dupe) {
        munmap(base, baseSize);
        close(f);
        return 1;
    }

    memcpy(dupe, base, baseSize);

    int result = 0;
    uint32_t magic = *(uint32_t *)base;
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        bool isBigEndian = (magic == FAT_CIGAM);
        struct fat_header *fatHeader = (struct fat_header *)base;
        struct fat_arch *fatArches = (struct fat_arch *)(fatHeader + 1);
        auto fatInt = [isBigEndian](uint32_t value) -> uint32_t {
            return isBigEndian ? OSSwapInt32(value) : value;
        };

        uint32_t nfatArch = fatInt(fatHeader->nfat_arch);
        FDLOG(@"fat binary with %u architectures", nfatArch);
        for (uint32_t i = 0; i < nfatArch; i++) {
            struct fat_arch *arch = &fatArches[i];
            uint32_t archOffset = fatInt(arch->offset);
            uint32_t archSize = fatInt(arch->size);
            if ((size_t)archOffset + archSize > baseSize ||
                (size_t)archOffset + sizeof(uint32_t) > baseSize) {
                FDLOG(@"fat arch %u is out of bounds", i);
                result = 1;
                continue;
            }
            // iOS 15 only runs arm64; 32-bit slices cannot be FairPlay-decrypted
            // here (mremap_encrypted has no 32-bit backend) and must not make the
            // whole image fail when the arm64 slice decrypts correctly.
            uint32_t archCpu = fatInt(arch->cputype);
            if (!(archCpu & CPU_ARCH_ABI64)) {
                FDLOG(@"skipping 32-bit fat arch %u (cpu=0x%x)", i, archCpu);
                continue;
            }
            if (td_fd_decryptMachoSlice(f, base + archOffset, dupe + archOffset, archOffset) != 0) {
                FDLOG(@"failed to decrypt fat arch %u", i);
                result = 1;
            }
        }
    } else {
        result = td_fd_decryptMachoSlice(f, base, dupe, 0);
    }

    munmap(base, baseSize);
    munmap(dupe, dupeSize);
    close(f);
    return result;
}

// ---------------------------------------------------------------------------
// Public Objective-C entry point used by TDDecryptionTask.
// ---------------------------------------------------------------------------
BOOL TDDecryptMachOWithFoulDecrypt(NSString *inputPath, NSString *outputPath) {
    if (inputPath.length == 0 || outputPath.length == 0) {
        return NO;
    }

    const char *inPath = [inputPath fileSystemRepresentation];
    const char *outPath = [outputPath fileSystemRepresentation];
    if (!inPath || !outPath) {
        return NO;
    }

    int rc = td_fd_decryptMachO(inPath, outPath);
    if (rc != 0) {
        FDLOG(@"decryption failed for %@ (rc=%d)", inputPath, rc);
        return NO;
    }

    FDLOG(@"successfully decrypted %@", inputPath);
    return YES;
}
