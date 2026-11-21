//
//  FoulDecrypt.h
//  TrollDecrypt
//
//  Port of the FoulDecrypt15 static decryption method.
//
//  The original FoulDecrypt tool decrypts a Mach-O directly from disk with the
//  private mremap_encrypted() syscall. When a slice's cryptoff is not 16K
//  aligned, it additionally uses the kerninfra kernel read/write framework to
//  patch Apple's "apple_protect_pager" so the syscall can decrypt the pages.
//
//  This module is intentionally UI-agnostic: it only converts one encrypted
//  Mach-O file into a decrypted copy. The app-level work (locating images,
//  copying bundles, building the IPA) remains in TDDecryptionTask.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Lazily initializes the kerninfra kernel R/W backend (libkrw provider).
/// Returns YES if kernel R/W is available, NO otherwise.
BOOL TDFoulDecryptKernelAvailable(void);

/// Decrypt the encrypted Mach-O at inputPath into outputPath.
///
/// Supports thin (MH_MAGIC/MH_MAGIC_64) and 32-bit fat (FAT_MAGIC/FAT_CIGAM)
/// binaries. If the file is not encrypted (cryptid == 0), it is simply copied.
///
/// Returns YES on success, NO on any failure. On failure the caller should
/// fall back to the live-process (task_for_pid) decryption path.
BOOL TDDecryptMachOWithFoulDecrypt(NSString *inputPath, NSString *outputPath);

NS_ASSUME_NONNULL_END
