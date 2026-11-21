#include <stdint.h>
#include "libkrw/include/libkrw.h"

uint32_t kernel_read32(uint64_t where) {
    uint32_t out = 0;
    kread(where, &out, sizeof(uint32_t));
    return out;
}

uint64_t kernel_read64(uint64_t where) {
    uint64_t out = 0;
    kread(where, &out, sizeof(uint64_t));
    return out;
}

void kernel_write32(uint64_t where, uint32_t what) {
    uint32_t _what = what;
	kwrite((void *)&_what, where, sizeof(uint32_t));
}

void kernel_write64(uint64_t where, uint64_t what) {
    uint64_t _what = what;
	kwrite((void *)&_what, where, sizeof(uint64_t));
}

void kernel_write(uint64_t where, const void *buf, size_t size) {
	kwrite((void *)buf, where, size);
}

void kernel_read(uint64_t where, void *buf, size_t size) {
	kread(where, buf, size);
}

void kernel_getbase(uint64_t *retkbase, uint64_t *retkslide) {
    uint64_t curKbase = 0;
    kbase(&curKbase);
	*retkbase = curKbase;
	*retkslide = 0;
}

int rw_prov_init() {
    // libkrw is weak-linked. If it is missing or unusable on this device its
    // symbols resolve to NULL. Fail cleanly so init_kerninfra() reports the
    // error and FoulDecrypt falls back to task_for_pid instead of calling a
    // NULL function pointer.
    if (!kbase || !kread || !kwrite) {
        return 1;
    }
    uint64_t kbaseAddr = 0;
    if (kbase(&kbaseAddr) != 0 || kbaseAddr == 0) {
        return 1;
    }
    return 0;
}