// Create env_shim_enhanced.c with this content:
#define _GNU_SOURCE
#include <dlfcn.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char *(*real_getenv)(const char *name);
static char *(*real_secure_getenv)(const char *name);

// Case-insensitive substring search
static bool contains_blocked(const char *str, const char *sub) {
    if (!str || !sub) return false;
    
    const char *s = str;
    while (*s) {
        const char *p = s;
        const char *q = sub;
        
        while (*p && *q && (toupper(*p) == toupper(*q))) {
            p++;
            q++;
        }
        
        if (*q == '\0') return true;
        s++;
    }
    return false;
}

static bool should_block(const char *name) {
    if (!name) return false;
    
    const char *blocked_patterns[] = {"PASSWORD", "KEY", "SECRET", NULL};
    
    for (int i = 0; blocked_patterns[i] != NULL; i++) {
        if (contains_blocked(name, blocked_patterns[i])) {
            return true;
        }
    }
    return false;
}

__attribute__((constructor))
static void init(void) {
    real_getenv = dlsym(RTLD_NEXT, "getenv");
    real_secure_getenv = dlsym(RTLD_NEXT, "secure_getenv");
    
    fprintf(stderr, "SEC-001: Environment filter loaded (PID: %d)\n", getpid());
}

char *getenv(const char *name) {
    if (!real_getenv) real_getenv = dlsym(RTLD_NEXT, "getenv");
    
    if (should_block(name)) {
        fprintf(stderr, "SEC-001 VIOLATION: Blocked getenv('%s')\n", name);
        errno = ENOENT;
        return NULL;
    }
    
    char *result = real_getenv(name);
    fprintf(stderr, "SEC-001: Allowed getenv('%s') = %s\n", name, result ? "[HIDDEN]" : "NULL");
    return result;
}

char *secure_getenv(const char *name) {
    if (!real_secure_getenv) real_secure_getenv = dlsym(RTLD_NEXT, "secure_getenv");
    
    if (should_block(name)) {
        fprintf(stderr, "SEC-001 VIOLATION: Blocked secure_getenv('%s')\n", name);
        errno = ENOENT;
        return NULL;
    }
    
    char *result = real_secure_getenv(name);
    fprintf(stderr, "SEC-001: Allowed secure_getenv('%s') = %s\n", name, result ? "[HIDDEN]" : "NULL");
    return result;
}