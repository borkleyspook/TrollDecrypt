#include <stdint.h>
#include <stddef.h>
#include <dlfcn.h>
#include <stdio.h>

/*
 * libkrw provider for kerninfra.
 *
 * libkrw is loaded at RUNTIME with dlopen()/dlsym() rather than linked at
 * build time. This is deliberate: a LC_LOAD(_WEAK)_DYLIB reference to
 * @rpath/libkrw.0.dylib makes the binary depend on a jailbreak dylib, which
 * breaks TrollStore (.tipa) launches on stock iOS (or crashes in TrollStore's
 * dyld environment). With dlopen there is NO load-command dependency, so the
 * same binary launches cleanly everywhere, and kernel R/W is only attempted
 * on jailbroken devices where libkrw actually exists.
 */

typedef int (*td_krw_kbase_t)(uint64_t *);
typedef int (*td_krw_kread_t)(uint64_t, void *, size_t);
typedef int (*td_krw_kwrite_t)(void *, uint64_t, size_t);

static void *s_td_krw_handle = NULL;
static td_krw_kbase_t s_td_krw_kbase = NULL;
static td_krw_kread_t s_td_krw_kread = NULL;
static td_krw_kwrite_t s_td_krw_kwrite = NULL;
static int s_td_krw_initialized = 0;

static void td_krw_log(const char *msg) {
    /* stderr is captured by the iOS unified log, visible via `log stream`. */
    fprintf(stderr, "[FoulDecrypt][libkrw] %s\n", msg);
}

static void *td_krw_open(void) {
    /* Rootless (Dopamine, etc.) first, then rootful. */
    static const char *const kPaths[] = {
        "/var/jb/usr/lib/libkrw.0.dylib",
        "/var/jb/usr/lib/libkrw.dylib",
        "/usr/lib/libkrw.0.dylib",
        "/usr/lib/libkrw.dylib",
        NULL
    };
    for (int i = 0; kPaths[i] != NULL; i++) {
        void *handle = dlopen(kPaths[i], RTLD_NOW | RTLD_LOCAL);
        if (handle != NULL) {
            fprintf(stderr, "[FoulDecrypt][libkrw] loaded %s\n", kPaths[i]);
            return handle;
        }
    }
    fprintf(stderr, "[FoulDecrypt][libkrw] dlopen failed: %s\n", dlerror());
    return NULL;
}

int rw_prov_init() {
    if (s_td_krw_initialized) {
        return (s_td_krw_handle != NULL) ? 0 : 1;
    }
    s_td_krw_initialized = 1;

    s_td_krw_handle = td_krw_open();
    if (s_td_krw_handle == NULL) {
        td_krw_log("unavailable; kerninfra will be disabled (task_for_pid fallback)");
        return 1;
    }

    s_td_krw_kbase = (td_krw_kbase_t)dlsym(s_td_krw_handle, "kbase");
    s_td_krw_kread = (td_krw_kread_t)dlsym(s_td_krw_handle, "kread");
    s_td_krw_kwrite = (td_krw_kwrite_t)dlsym(s_td_krw_handle, "kwrite");
    if (s_td_krw_kbase == NULL || s_td_krw_kread == NULL || s_td_krw_kwrite == NULL) {
        td_krw_log("missing kbase/kread/kwrite symbols; disabling kerninfra");
        dlclose(s_td_krw_handle);
        s_td_krw_handle = NULL;
        return 1;
    }

    /* Verify libkrw is actually usable by reading the kernel base. */
    uint64_t kbaseAddr = 0;
    if (s_td_krw_kbase(&kbaseAddr) != 0 || kbaseAddr == 0) {
        td_krw_log("kbase() failed; disabling kerninfra");
        dlclose(s_td_krw_handle);
        s_td_krw_handle = NULL;
        s_td_krw_kbase = NULL;
        s_td_krw_kread = NULL;
        s_td_krw_kwrite = NULL;
        return 1;
    }

    td_krw_log("ready");
    return 0;
}

uint32_t kernel_read32(uint64_t where) {
    uint32_t out = 0;
    if (s_td_krw_kread != NULL) s_td_krw_kread(where, &out, sizeof(uint32_t));
    return out;
}

uint64_t kernel_read64(uint64_t where) {
    uint64_t out = 0;
    if (s_td_krw_kread != NULL) s_td_krw_kread(where, &out, sizeof(uint64_t));
    return out;
}

void kernel_write32(uint64_t where, uint32_t what) {
    uint32_t _what = what;
    if (s_td_krw_kwrite != NULL) s_td_krw_kwrite((void *)&_what, where, sizeof(uint32_t));
}

void kernel_write64(uint64_t where, uint64_t what) {
    uint64_t _what = what;
    if (s_td_krw_kwrite != NULL) s_td_krw_kwrite((void *)&_what, where, sizeof(uint64_t));
}

void kernel_write(uint64_t where, const void *buf, size_t size) {
    if (s_td_krw_kwrite != NULL) s_td_krw_kwrite((void *)buf, where, size);
}

void kernel_read(uint64_t where, void *buf, size_t size) {
    if (s_td_krw_kread != NULL) s_td_krw_kread(where, buf, size);
}

void kernel_getbase(uint64_t *retkbase, uint64_t *retkslide) {
    uint64_t curKbase = 0;
    if (s_td_krw_kbase != NULL) s_td_krw_kbase(&curKbase);
    *retkbase = curKbase;
    *retkslide = 0;
}
