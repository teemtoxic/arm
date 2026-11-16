/*
 * shim.c — builds a fake Android "liblog.so" so that libondevx.so can be
 * dlopen()'d on a normal Linux (aarch64) box.
 *
 * libondevx.so NEEDs: liblog.so, libm.so, libdl.so, libc.so
 * and imports the following symbols that do not exist on glibc:
 *
 *   __android_log_print        bionic logging
 *   __assert2                  bionic assert (file,line,func,expr)
 *   __memcpy_chk               FORTIFY
 *   __sF                       bionic's stderr/stdout FILE* array
 *   __system_property_get      Android property service
 *   android_set_abort_message  bionic crash annotation
 *
 * Those are provided here.  The libm.so / libdl.so / libc.so linker-script
 * problem is solved in the workflow by symlinking the real libm.so.6,
 * libdl.so.2 and libc.so.6 next to this file.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---- liblog ---- */
int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[android-log] %s: ", tag ? tag : "?");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    return 0;
}

int __android_log_write(int prio, const char *tag, const char *msg) {
    fprintf(stderr, "[android-log] %s: %s\n", tag ? tag : "?", msg ? msg : "");
    return 0;
}

int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list ap) {
    fprintf(stderr, "[android-log] %s: ", tag ? tag : "?");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    return 0;
}

int __android_log_assert(const char *cond, const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[android-assert] %s: %s: ", tag ? tag : "?", cond ? cond : "?");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    return 0;
}

void android_set_abort_message(const char *msg) {
    fprintf(stderr, "[android-abort] %s\n", msg ? msg : "");
}

/* ---- bionic assert ---- */
void __assert2(const char *file, int line, const char *func, const char *expr) {
    fprintf(stderr, "assertion failed: %s:%d %s: %s\n",
            file ? file : "?", line, func ? func : "?", expr ? expr : "?");
    abort();
}

/* ---- FORTIFY ---- */
void *__memcpy_chk(void *dst, const void *src, size_t n, size_t dstlen) {
    if (n > dstlen) {
        fprintf(stderr, "__memcpy_chk: %zu > %zu\n", n, dstlen);
        abort();
    }
    return memcpy(dst, src, n);
}

void *__memset_chk(void *dst, int c, size_t n, size_t dstlen) {
    if (n > dstlen) {
        fprintf(stderr, "__memset_chk: %zu > %zu\n", n, dstlen);
        abort();
    }
    return memset(dst, c, n);
}

char *__strcpy_chk(char *dst, const char *src, size_t dstlen) {
    size_t n = strlen(src) + 1;
    if (n > dstlen) { fprintf(stderr, "__strcpy_chk overflow\n"); abort(); }
    return memcpy(dst, src, n);
}

/* ---- bionic internals ---- */
/* bionic exposes stdin/stdout/stderr as an array of FILE structs. Any code that
 * touches __sF[2] (stderr) just wants a writable FILE*. */
static char sF_storage[3][512];
void *__sF = sF_storage;

int __system_property_get(const char *name, char *value) {
    /* Every anti-tamper probe goes through here: ro.build.tags, ro.debuggable,
     * ro.secure, ro.product.model, etc. Return "clean device" values. */
    if (!name || !value) return 0;
    const char *v = "";
    if      (!strcmp(name, "ro.build.tags"))            v = "release-keys";
    else if (!strcmp(name, "ro.debuggable"))            v = "0";
    else if (!strcmp(name, "ro.secure"))                v = "1";
    else if (!strcmp(name, "ro.product.manufacturer"))  v = "samsung";
    else if (!strcmp(name, "ro.product.model"))         v = "SM-G991B";
    else if (!strcmp(name, "ro.build.type"))            v = "user";
    else if (!strcmp(name, "ro.build.version.sdk"))     v = "34";
    else if (!strcmp(name, "ro.product.cpu.abi"))       v = "arm64-v8a";
    else if (!strcmp(name, "ro.board.platform"))        v = "exynos2100";
    else if (!strcmp(name, "init.svc.adbd"))            v = "stopped";
    size_t n = strlen(v);
    if (n > 91) n = 91;
    memcpy(value, v, n);
    value[n] = 0;
    return (int)n;
}
