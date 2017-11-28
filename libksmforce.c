/*
 * Force marking all memory allocated by programs as KSM-mergeable
 *
 * gcc -ggdb3 libksmforce.c -ldl -shared -fno-builtin-malloc -fPIC -o libksmforce.so
 * LD_PRELOAD=libksmforce.so ./program
 */

#define _GNU_SOURCE // for RTLD_NEXT in dlfcn.h
#include <dlfcn.h>  // for dlsym()
#include <stddef.h> // for size_t
#include <stdint.h> // for intptr_t
#include <stdio.h>  // for off_t
#include <unistd.h> // for _exit()
#include <stdarg.h> // for va_start()
#include <stdbool.h> // for bool
#include <sys/mman.h> // for madvise()

#define API extern __attribute__ ((visibility("default")))

static int initing = false;
static int inited = false;

typedef void* (libc_malloc_t)(size_t);
typedef void  (libc_free_t)(void*);
typedef void* (libc_calloc_t)(size_t, size_t);
typedef void* (libc_realloc_t)(void*, size_t);
typedef void* (libc_mmap_t)(void*, size_t, int, int, int, off_t);
typedef int   (libc_munmap_t)(void*, size_t);
typedef void* (libc_mremap_t)(void*, size_t, size_t, int, ...);

static libc_malloc_t  *libc_malloc = NULL;
static libc_free_t    *libc_free = NULL;
static libc_calloc_t  *libc_calloc = NULL;
static libc_realloc_t *libc_realloc = NULL;
static libc_mmap_t    *libc_mmap = NULL;
static libc_munmap_t  *libc_munmap = NULL;
static libc_mremap_t  *libc_mremap = NULL;

extern libc_malloc_t __libc_malloc;

#define ASSIGN_DLSYM_OR_DIE(name)                                           \
        libc_##name = (libc_##name##_##t*)(intptr_t)dlsym(RTLD_NEXT, #name); \
        if (!libc_##name || dlerror())                                      \
                _exit(1);

#define ASSIGN_DLSYM_IF_EXIST(name)                                         \
        libc_##name = (libc_##name##_##t*)(intptr_t)dlsym(RTLD_NEXT, #name); \
                                                   dlerror();

static inline void libksmforce_init(void)
{
    if (inited) return;
    if (initing) return;
    initing = true;
    ASSIGN_DLSYM_OR_DIE(malloc);
    ASSIGN_DLSYM_OR_DIE(free);
    ASSIGN_DLSYM_OR_DIE(calloc);
    ASSIGN_DLSYM_OR_DIE(realloc);
    ASSIGN_DLSYM_OR_DIE(mmap);
    ASSIGN_DLSYM_OR_DIE(munmap);
    ASSIGN_DLSYM_OR_DIE(mremap);
    inited = true;
    initing = false;
}

static const size_t pagesize = 4096;
static void ksmforce(void* ptr, size_t length) {
    if (ptr == NULL) return;

    const uintptr_t addr = (uintptr_t)ptr;
    const uintptr_t aligned = (addr / pagesize) * pagesize;
    // round up to page size
    length += pagesize-1;
    length &= (~(pagesize-1));
    // ignore return value
    (void)madvise((void*)aligned, length, MADV_MERGEABLE);
}

API void* malloc(size_t size) {
    libksmforce_init();
    if (libc_malloc == NULL) return NULL;
    void* retval = (*libc_malloc)(size);
    ksmforce(retval, size);
    return retval;
}

static unsigned char buffer[8192];
API void free(void *ptr) {
    if (ptr == buffer) return;
    libksmforce_init();
    if (libc_free == NULL) return;
    (*libc_free)(ptr);
}

API void* calloc(size_t nmemb, size_t size) {
    if (libc_calloc == NULL) {
        return buffer;
    }
    libksmforce_init();
    void* retval = (*libc_calloc)(nmemb, size);
    ksmforce(retval, nmemb*size);
    return retval;
}

API void* realloc(void* ptr, size_t size) {
    libksmforce_init();
    if (libc_realloc == NULL) return NULL;
    void* retval = (*libc_realloc)(ptr, size);
    ksmforce(retval, size);
    return retval;
}

API void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    libksmforce_init();
    if (libc_mmap == NULL) return NULL;
    void* retval = (*libc_mmap)(addr, length, prot, flags, fd, offset);
    ksmforce(retval, length);
    return retval;
}

API int munmap(void* addr, size_t length) {
    libksmforce_init();
    if (libc_munmap == NULL) return 0;
    return (*libc_munmap)(addr, length);
}

API void* mremap(void* old_address, size_t old_size, size_t new_size, int flags, ...) {
    libksmforce_init();
    if (libc_mremap == NULL) return NULL;
    void *new_address;
    va_list ap;
    va_start(ap, flags);
    new_address = va_arg(ap, void*);
    va_end(ap);
    void* retval = (*libc_mremap)(old_address, old_size, new_size, flags, new_address);
    ksmforce(retval, new_size);
    return retval;
}
