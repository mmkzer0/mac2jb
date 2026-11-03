/*
 * kext-s3-probe: unprivileged IOKit boundary probe for the pinned, self-built usbgadget.kext.
 *
 * Turns the S3 boundary checks of docs/kext-hardening-plan.md section 8 into reproducible,
 * machine-readable evidence. See docs/kext-s3-probe.md for the contract, subcommands, exit codes
 * and the S3 run order.
 *
 * Properties this program keeps by construction:
 *   - it never installs, loads or unloads a kext and needs no root (guarded commands refuse root);
 *   - it never sends a valid PublishConfiguration: the only dictionaries it writes are
 *     {"Poke":"Poke"} (a no-op without a published configuration) and deliberately invalid inputs;
 *   - open-close, poke and reject verify that the loaded gay.bowser.usbgadget carries exactly the
 *     pinned LC_UUID before they enumerate services, open a connection or write a property;
 *   - stdout carries JSON lines only (one object per event, last line = summary); diagnostics go to
 *     stderr.
 */
#define _DARWIN_C_SOURCE 1

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOReturn.h>
#include <IOKit/kext/KextManager.h>
#include <mach/mach.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define BUNDLE_ID "gay.bowser.usbgadget"
#define SERVICE_CLASS "gay_bowser_usbgadget"
#define USERCLIENT_CLASS "gay_bowser_usbgadget_userclient"
#define DEFAULT_PROVENANCE "drivers/PROVENANCE"

/* Exit codes (documented in docs/kext-s3-probe.md). */
enum {
    RC_OK = 0,
    RC_ERROR = 1,
    RC_NOT_LOADED = 2,
    RC_MISMATCH = 3,
    RC_NO_SERVICE = 4,
    RC_LEAK = 5,
    RC_HANG = 6,
    RC_ACCEPTED = 7,
};

/* Input bounds. */
#define ITERATIONS_MAX 100000u
#define THREADS_MAX 64u
#define SETTLE_MS_MAX 60000u
#define SETTLE_MS_DEFAULT 2000u
#define CALL_TIMEOUT_MS_MAX 600000u
#define CALL_TIMEOUT_MS_DEFAULT 5000u
#define SVC_MAX 32u
#define LOADED_MAX 8u
#define PROV_MAX 4096u

static void eprintf_(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void eprintf_(const char *fmt, ...)
{
    va_list ap;
    fputs("kext-s3-probe: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* ------------------------------------------------------------------------------------------ */
/* JSON-lines emitter                                                                          */
/* ------------------------------------------------------------------------------------------ */

#define JB_CAP 16384u

struct jb {
    char buf[JB_CAP];
    size_t len;
    bool overflow;
    bool after_key;
};

static pthread_mutex_t g_out_lock = PTHREAD_MUTEX_INITIALIZER;

static void jb_init(struct jb *j)
{
    j->len = 0;
    j->buf[0] = '\0';
    j->overflow = false;
    j->after_key = false;
}

static void jb_put(struct jb *j, const char *s, size_t n)
{
    if (j->overflow) {
        return;
    }
    /* Keep room for the closing brace, the newline and the NUL. */
    if (n > JB_CAP - 4 - j->len) {
        j->overflow = true;
        return;
    }
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
}

static void jb_sep(struct jb *j)
{
    if (j->after_key) {
        j->after_key = false;
        return;
    }
    if (j->len > 0 && j->buf[j->len - 1] != '{' && j->buf[j->len - 1] != '[') {
        jb_put(j, ",", 1);
    }
}

/* Quote a C string. Bytes outside printable ASCII become \u00XX so the line is always valid JSON
 * even when a path or registry name is not UTF-8. */
static void jb_quoted(struct jb *j, const char *s)
{
    jb_put(j, "\"", 1);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        char tmp[8];
        if (*p == '"' || *p == '\\') {
            tmp[0] = '\\';
            tmp[1] = (char)*p;
            jb_put(j, tmp, 2);
        } else if (*p < 0x20 || *p >= 0x7f) {
            int n = snprintf(tmp, sizeof tmp, "\\u%04x", (unsigned)*p);
            jb_put(j, tmp, (size_t)n);
        } else {
            tmp[0] = (char)*p;
            jb_put(j, tmp, 1);
        }
    }
    jb_put(j, "\"", 1);
}

static void jb_open(struct jb *j, char c)
{
    jb_sep(j);
    jb_put(j, &c, 1);
}

static void jb_close(struct jb *j, char c)
{
    jb_put(j, &c, 1);
}

static void jb_key(struct jb *j, const char *k)
{
    jb_sep(j);
    jb_quoted(j, k);
    jb_put(j, ":", 1);
    j->after_key = true;
}

static void jb_str(struct jb *j, const char *v)
{
    jb_sep(j);
    jb_quoted(j, v);
}

static void jb_u64(struct jb *j, uint64_t v)
{
    char tmp[32];
    jb_sep(j);
    int n = snprintf(tmp, sizeof tmp, "%llu", (unsigned long long)v);
    jb_put(j, tmp, (size_t)n);
}

static void jb_bool(struct jb *j, bool v)
{
    jb_sep(j);
    jb_put(j, v ? "true" : "false", v ? 4 : 5);
}

static void jb_null(struct jb *j)
{
    jb_sep(j);
    jb_put(j, "null", 4);
}

static void jb_hex32(struct jb *j, uint32_t v)
{
    char tmp[16];
    snprintf(tmp, sizeof tmp, "0x%08x", v);
    jb_sep(j);
    jb_quoted(j, tmp);
}

static void jb_kstr(struct jb *j, const char *k, const char *v)
{
    jb_key(j, k);
    jb_str(j, v);
}

static void jb_ku64(struct jb *j, const char *k, uint64_t v)
{
    jb_key(j, k);
    jb_u64(j, v);
}

static void jb_kbool(struct jb *j, const char *k, bool v)
{
    jb_key(j, k);
    jb_bool(j, v);
}

static void jb_khex32(struct jb *j, const char *k, uint32_t v)
{
    jb_key(j, k);
    jb_hex32(j, v);
}

/* Start an event object: {"event":"<name>" */
static void jb_event(struct jb *j, const char *name)
{
    jb_init(j);
    jb_open(j, '{');
    jb_kstr(j, "event", name);
}

static bool jb_emit(struct jb *j)
{
    if (j->overflow) {
        eprintf_("internal error: JSON line exceeds %u bytes", JB_CAP);
        return false;
    }
    jb_close(j, '}');
    jb_put(j, "\n", 1);
    if (j->overflow) {
        eprintf_("internal error: JSON line exceeds %u bytes", JB_CAP);
        return false;
    }
    pthread_mutex_lock(&g_out_lock);
    size_t w = fwrite(j->buf, 1, j->len, stdout);
    int fl = fflush(stdout);
    pthread_mutex_unlock(&g_out_lock);
    return w == j->len && fl == 0;
}

/* ------------------------------------------------------------------------------------------ */
/* Return-code names and histograms                                                            */
/* ------------------------------------------------------------------------------------------ */

static const char *kr_name(uint32_t kr)
{
    switch (kr) {
    case (uint32_t)KERN_SUCCESS: return "success";
    case (uint32_t)kIOReturnError: return "kIOReturnError";
    case (uint32_t)kIOReturnNoMemory: return "kIOReturnNoMemory";
    case (uint32_t)kIOReturnNoResources: return "kIOReturnNoResources";
    case (uint32_t)kIOReturnNoDevice: return "kIOReturnNoDevice";
    case (uint32_t)kIOReturnNotPrivileged: return "kIOReturnNotPrivileged";
    case (uint32_t)kIOReturnBadArgument: return "kIOReturnBadArgument";
    case (uint32_t)kIOReturnExclusiveAccess: return "kIOReturnExclusiveAccess";
    case (uint32_t)kIOReturnUnsupported: return "kIOReturnUnsupported";
    case (uint32_t)kIOReturnNotOpen: return "kIOReturnNotOpen";
    case (uint32_t)kIOReturnBusy: return "kIOReturnBusy";
    case (uint32_t)kIOReturnTimeout: return "kIOReturnTimeout";
    case (uint32_t)kIOReturnOffline: return "kIOReturnOffline";
    case (uint32_t)kIOReturnNotReady: return "kIOReturnNotReady";
    case (uint32_t)kIOReturnNotAttached: return "kIOReturnNotAttached";
    case (uint32_t)kIOReturnAborted: return "kIOReturnAborted";
    case (uint32_t)kIOReturnNotPermitted: return "kIOReturnNotPermitted";
    case (uint32_t)kIOReturnNotFound: return "kIOReturnNotFound";
    case (uint32_t)MACH_SEND_INVALID_DEST: return "MACH_SEND_INVALID_DEST";
    default: return "unknown";
    }
}

#define HIST_MAX 24u

struct hist {
    uint32_t code[HIST_MAX];
    uint64_t count[HIST_MAX];
    size_t n;
    uint64_t overflow; /* calls whose code did not fit into the table */
};

static void hist_add_n(struct hist *h, uint32_t code, uint64_t c)
{
    for (size_t i = 0; i < h->n; i++) {
        if (h->code[i] == code) {
            h->count[i] += c;
            return;
        }
    }
    if (h->n < HIST_MAX) {
        h->code[h->n] = code;
        h->count[h->n] = c;
        h->n++;
    } else {
        h->overflow += c;
    }
}

static void hist_add(struct hist *h, uint32_t code)
{
    hist_add_n(h, code, 1);
}

static void hist_merge(struct hist *dst, const struct hist *src)
{
    for (size_t i = 0; i < src->n; i++) {
        hist_add_n(dst, src->code[i], src->count[i]);
    }
    dst->overflow += src->overflow;
}

static uint64_t hist_total(const struct hist *h)
{
    uint64_t t = h->overflow;
    for (size_t i = 0; i < h->n; i++) {
        t += h->count[i];
    }
    return t;
}

static uint64_t hist_of(const struct hist *h, uint32_t code)
{
    for (size_t i = 0; i < h->n; i++) {
        if (h->code[i] == code) {
            return h->count[i];
        }
    }
    return 0;
}

static void jb_hist(struct jb *j, const char *key, const struct hist *h)
{
    jb_key(j, key);
    jb_open(j, '[');
    for (size_t i = 0; i < h->n; i++) {
        jb_open(j, '{');
        jb_khex32(j, "code", h->code[i]);
        jb_kstr(j, "name", kr_name(h->code[i]));
        jb_ku64(j, "count", h->count[i]);
        jb_close(j, '}');
    }
    if (h->overflow) {
        jb_open(j, '{');
        jb_kstr(j, "code", "other");
        jb_ku64(j, "count", h->overflow);
        jb_close(j, '}');
    }
    jb_close(j, ']');
}

/* ------------------------------------------------------------------------------------------ */
/* UUID and numeric parsing                                                                    */
/* ------------------------------------------------------------------------------------------ */

static int hex_val(char c, bool upper_only)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (!upper_only && c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

/* Strict 8-4-4-4-12 hexadecimal UUID. upper_only rejects a-f (PROVENANCE is uppercase by contract). */
static bool uuid_parse_text(const char *s, size_t n, bool upper_only, uint8_t out[16])
{
    if (n != 36) {
        return false;
    }
    size_t bi = 0;
    for (size_t i = 0; i < 36;) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') {
                return false;
            }
            i++;
            continue;
        }
        int hi = hex_val(s[i], upper_only);
        int lo = hex_val(s[i + 1], upper_only);
        if (hi < 0 || lo < 0 || s[i + 1] == '-') {
            return false;
        }
        out[bi++] = (uint8_t)(hi << 4 | lo);
        i += 2;
    }
    return bi == 16;
}

static void uuid_to_text(const uint8_t u[16], char out[37])
{
    snprintf(out, 37, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", u[0], u[1], u[2],
             u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

/* Plain decimal digits only: no sign, space, prefix or suffix; range-checked. */
static bool parse_dec(const char *s, uint64_t min, uint64_t max, uint64_t *out)
{
    size_t n = strlen(s);
    if (n == 0 || n > 20) {
        return false;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        uint64_t d = (uint64_t)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10) {
            return false;
        }
        v = v * 10 + d;
    }
    if (v < min || v > max) {
        return false;
    }
    *out = v;
    return true;
}

/* Registry entry ID: nonzero, decimal or 0x-prefixed hexadecimal (at most 16 digits). */
static bool parse_entry_id(const char *s, uint64_t *out)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        const char *p = s + 2;
        size_t n = strlen(p);
        if (n == 0 || n > 16) {
            return false;
        }
        uint64_t v = 0;
        for (size_t i = 0; i < n; i++) {
            int h = hex_val(p[i], false);
            if (h < 0) {
                return false;
            }
            v = v << 4 | (uint64_t)h;
        }
        if (v == 0) {
            return false;
        }
        *out = v;
        return true;
    }
    return parse_dec(s, 1, UINT64_MAX, out);
}

/* ------------------------------------------------------------------------------------------ */
/* drivers/PROVENANCE parser                                                                   */
/* ------------------------------------------------------------------------------------------ */

enum { PK_FORMAT, PK_BUNDLE, PK_EXE_SHA, PK_PLIST_SHA, PK_UUID, PK_TREE_SHA, PK_COMMIT, PK_XCODE, PK_SDK, PK_COUNT };

static const char *const PROV_KEYS[PK_COUNT] = {
    "format",      "bundle_identifier", "executable_sha256", "info_plist_sha256", "lc_uuid",
    "source_tree_sha256", "source_commit", "xcode_build",    "sdk_build",
};

struct provenance {
    uint8_t lc_uuid[16];
};

static bool is_lower_hex(const char *s, size_t n, size_t want)
{
    if (n != want) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool is_build_token(const char *s, size_t n)
{
    if (n == 0 || n > 32) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' ||
                  c == '_' || c == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

static bool prov_value_ok(int key, const char *v, size_t n, struct provenance *out)
{
    switch (key) {
    case PK_FORMAT: return n == strlen("mac2jb-bundled-kext-v1") && memcmp(v, "mac2jb-bundled-kext-v1", n) == 0;
    case PK_BUNDLE: return n == strlen(BUNDLE_ID) && memcmp(v, BUNDLE_ID, n) == 0;
    case PK_EXE_SHA:
    case PK_PLIST_SHA:
    case PK_TREE_SHA: return is_lower_hex(v, n, 64);
    case PK_UUID: return uuid_parse_text(v, n, true, out->lc_uuid);
    case PK_COMMIT: return is_lower_hex(v, n, 40);
    case PK_XCODE:
    case PK_SDK: return is_build_token(v, n);
    default: return false;
    }
}

/* Parse the exact PROVENANCE layout: nine `key=value` lines in contract order, LF-terminated, each
 * key once, value = everything after the first '='. Any deviation fails closed with a message. */
static bool prov_parse(const char *buf, size_t len, struct provenance *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof *out);
    if (len == 0) {
        snprintf(err, errlen, "PROVENANCE is empty");
        return false;
    }
    if (memchr(buf, '\0', len)) {
        snprintf(err, errlen, "PROVENANCE contains a NUL byte");
        return false;
    }
    if (memchr(buf, '\r', len)) {
        snprintf(err, errlen, "PROVENANCE contains a CR byte (LF line endings required)");
        return false;
    }
    if (buf[len - 1] != '\n') {
        snprintf(err, errlen, "PROVENANCE does not end with LF");
        return false;
    }
    bool seen[PK_COUNT] = {false};
    size_t pos = 0;
    size_t line = 0;
    while (pos < len) {
        line++;
        const char *nl = memchr(buf + pos, '\n', len - pos);
        size_t end = (size_t)(nl - buf); /* nl is non-NULL: the buffer ends with LF */
        const char *eq = memchr(buf + pos, '=', end - pos);
        if (!eq) {
            snprintf(err, errlen, "line %zu: no '='", line);
            return false;
        }
        size_t klen = (size_t)(eq - (buf + pos));
        int key = -1;
        for (int k = 0; k < PK_COUNT; k++) {
            if (klen == strlen(PROV_KEYS[k]) && memcmp(buf + pos, PROV_KEYS[k], klen) == 0) {
                key = k;
                break;
            }
        }
        if (key < 0) {
            snprintf(err, errlen, "line %zu: unknown key '%.*s'", line, (int)(klen > 40 ? 40 : klen), buf + pos);
            return false;
        }
        if (seen[key]) {
            snprintf(err, errlen, "line %zu: duplicate key '%s'", line, PROV_KEYS[key]);
            return false;
        }
        if ((size_t)key != line - 1) {
            snprintf(err, errlen, "line %zu: key '%s' out of order (expected '%s')", line, PROV_KEYS[key],
                     line <= PK_COUNT ? PROV_KEYS[line - 1] : "end of file");
            return false;
        }
        seen[key] = true;
        const char *val = eq + 1;
        size_t vlen = (size_t)((buf + end) - val);
        if (!prov_value_ok(key, val, vlen, out)) {
            snprintf(err, errlen, "line %zu: invalid value for '%s'", line, PROV_KEYS[key]);
            return false;
        }
        pos = end + 1;
    }
    if (line != PK_COUNT) {
        snprintf(err, errlen, "missing key '%s' (found %zu of %d lines)", PROV_KEYS[line], line, PK_COUNT);
        return false;
    }
    return true;
}

static bool read_file_limited(const char *path, char *buf, size_t cap, size_t *len, char *err, size_t errlen)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return false;
    }
    size_t n = fread(buf, 1, cap, f);
    bool bad = ferror(f) != 0;
    fclose(f);
    if (bad) {
        snprintf(err, errlen, "cannot read %s", path);
        return false;
    }
    if (n > PROV_MAX) {
        snprintf(err, errlen, "%s is larger than %u bytes", path, PROV_MAX);
        return false;
    }
    *len = n;
    return true;
}

/* ------------------------------------------------------------------------------------------ */
/* Command line                                                                                */
/* ------------------------------------------------------------------------------------------ */

enum cmd { CMD_IDENTITY, CMD_INVENTORY, CMD_OPEN_CLOSE, CMD_POKE, CMD_REJECT, CMD_SELF_TEST };

enum {
    F_PROV = 1u << 0,
    F_UUID = 1u << 1,
    F_ITER = 1u << 2,
    F_THREADS = 1u << 3,
    F_SETTLE = 1u << 4,
    F_TIMEOUT = 1u << 5,
    F_ENTRY = 1u << 6,
};

struct flagdef {
    const char *name;
    unsigned bit;
};

static const struct flagdef FLAGS[] = {
    {"--provenance", F_PROV}, {"--uuid", F_UUID},         {"--iterations", F_ITER},
    {"--threads", F_THREADS}, {"--settle-ms", F_SETTLE},  {"--call-timeout-ms", F_TIMEOUT},
    {"--entry-id", F_ENTRY},
};

struct cmddef {
    const char *name;
    enum cmd cmd;
    unsigned allowed;
    unsigned required;
};

static const struct cmddef CMDS[] = {
    {"identity", CMD_IDENTITY, F_PROV | F_UUID, 0},
    {"inventory", CMD_INVENTORY, 0, 0},
    {"open-close", CMD_OPEN_CLOSE, F_PROV | F_UUID | F_ITER | F_ENTRY | F_SETTLE, F_ITER},
    {"poke", CMD_POKE, F_PROV | F_UUID | F_ITER | F_THREADS | F_ENTRY | F_TIMEOUT, F_ITER | F_THREADS},
    {"reject", CMD_REJECT, F_PROV | F_UUID | F_ENTRY, 0},
    {"self-test", CMD_SELF_TEST, 0, 0},
};

struct opts {
    const char *provenance; /* NULL = default path */
    bool have_uuid;
    uint8_t uuid[16];
    uint64_t iterations;
    uint64_t threads;
    uint64_t settle_ms;
    uint64_t call_timeout_ms;
    uint64_t entry_id; /* 0 = all gadget services */
};

static const struct cmddef *find_cmd(const char *name)
{
    for (size_t i = 0; i < sizeof CMDS / sizeof CMDS[0]; i++) {
        if (strcmp(CMDS[i].name, name) == 0) {
            return &CMDS[i];
        }
    }
    return NULL;
}

static bool parse_opts(const struct cmddef *def, int argc, const char *const *argv, struct opts *o, char *err,
                       size_t errlen)
{
    memset(o, 0, sizeof *o);
    o->settle_ms = SETTLE_MS_DEFAULT;
    o->call_timeout_ms = CALL_TIMEOUT_MS_DEFAULT;
    unsigned seen = 0;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        const struct flagdef *fd = NULL;
        for (size_t k = 0; k < sizeof FLAGS / sizeof FLAGS[0]; k++) {
            if (strcmp(a, FLAGS[k].name) == 0) {
                fd = &FLAGS[k];
                break;
            }
        }
        if (!fd) {
            snprintf(err, errlen, a[0] == '-' ? "unknown flag '%s'" : "unexpected argument '%s'", a);
            return false;
        }
        if (!(def->allowed & fd->bit)) {
            snprintf(err, errlen, "flag '%s' is not valid for '%s'", a, def->name);
            return false;
        }
        if (seen & fd->bit) {
            snprintf(err, errlen, "flag '%s' given more than once", a);
            return false;
        }
        if (i + 1 >= argc || strncmp(argv[i + 1], "--", 2) == 0) {
            snprintf(err, errlen, "flag '%s' needs a value", a);
            return false;
        }
        const char *v = argv[++i];
        seen |= fd->bit;
        bool ok = true;
        switch (fd->bit) {
        case F_PROV: o->provenance = v; break;
        case F_UUID: ok = uuid_parse_text(v, strlen(v), false, o->uuid); o->have_uuid = ok; break;
        case F_ITER: ok = parse_dec(v, 1, ITERATIONS_MAX, &o->iterations); break;
        case F_THREADS: ok = parse_dec(v, 1, THREADS_MAX, &o->threads); break;
        case F_SETTLE: ok = parse_dec(v, 0, SETTLE_MS_MAX, &o->settle_ms); break;
        case F_TIMEOUT: ok = parse_dec(v, 1, CALL_TIMEOUT_MS_MAX, &o->call_timeout_ms); break;
        case F_ENTRY: ok = parse_entry_id(v, &o->entry_id); break;
        default: ok = false; break;
        }
        if (!ok) {
            snprintf(err, errlen, "invalid value '%.64s' for '%s'", v, a);
            return false;
        }
    }
    if (def->required & ~seen) {
        for (size_t k = 0; k < sizeof FLAGS / sizeof FLAGS[0]; k++) {
            if ((def->required & ~seen) & FLAGS[k].bit) {
                snprintf(err, errlen, "'%s' requires %s", def->name, FLAGS[k].name);
                return false;
            }
        }
    }
    if ((seen & F_PROV) && (seen & F_UUID)) {
        snprintf(err, errlen, "--provenance and --uuid are mutually exclusive");
        return false;
    }
    return true;
}

static void usage(FILE *f)
{
    fputs("usage: kext-s3-probe <command> [flags]\n"
          "  identity   [--provenance PATH | --uuid UUID]\n"
          "  inventory\n"
          "  open-close --iterations N [--entry-id ID] [--settle-ms MS] [--provenance PATH | --uuid UUID]\n"
          "  poke       --iterations N --threads K [--entry-id ID] [--call-timeout-ms T] [--provenance PATH | --uuid UUID]\n"
          "  reject     [--entry-id ID] [--provenance PATH | --uuid UUID]\n"
          "  self-test\n"
          "bounds: iterations 1..100000, threads 1..64, settle-ms 0..60000, call-timeout-ms 1..600000\n"
          "stdout: JSON lines; stderr: diagnostics; exit codes: see docs/kext-s3-probe.md\n",
          f);
}

/* ------------------------------------------------------------------------------------------ */
/* Events common to all commands                                                               */
/* ------------------------------------------------------------------------------------------ */

static void sysctl_str(const char *name, char *out, size_t cap)
{
    size_t n = cap;
    if (sysctlbyname(name, out, &n, NULL, 0) != 0 || n == 0) {
        snprintf(out, cap, "unknown");
        return;
    }
    out[cap - 1] = '\0';
}

static void emit_start(const char *command)
{
    struct jb j;
    char ver[64];
    char build[64];
    jb_event(&j, "start");
    jb_kstr(&j, "command", command);
    jb_ku64(&j, "uid", (uint64_t)getuid());
    jb_ku64(&j, "euid", (uint64_t)geteuid());
    jb_ku64(&j, "pid", (uint64_t)getpid());
    jb_ku64(&j, "unix_time", (uint64_t)time(NULL));
    sysctl_str("kern.osproductversion", ver, sizeof ver);
    sysctl_str("kern.osversion", build, sizeof build);
    jb_kstr(&j, "os_version", ver);
    jb_kstr(&j, "os_build", build);
    jb_emit(&j);
}

static void emit_summary(const char *command, const char *status, int rc, int64_t services)
{
    struct jb j;
    jb_event(&j, "summary");
    jb_kstr(&j, "command", command);
    jb_kstr(&j, "status", status);
    jb_kbool(&j, "ok", rc == RC_OK);
    jb_ku64(&j, "exit", (uint64_t)rc);
    if (services >= 0) {
        jb_ku64(&j, "services", (uint64_t)services);
    }
    jb_emit(&j);
}

/* ------------------------------------------------------------------------------------------ */
/* Loaded-kext identity                                                                        */
/* ------------------------------------------------------------------------------------------ */

struct loaded {
    size_t count; /* loaded kexts with CFBundleIdentifier == BUNDLE_ID */
    size_t nuuid; /* valid 16-byte OSBundleUUIDs collected (up to LOADED_MAX) */
    uint8_t uuids[LOADED_MAX][16];
    bool bad_uuid; /* a matching entry had no readable 16-byte OSBundleUUID */
};

/* Pure decision: map what is loaded and what is pinned to an exit code and a status token. */
static int classify_identity(const struct loaded *l, const uint8_t pin[16], const char **status)
{
    if (l->count == 0) {
        *status = "not-loaded";
        return RC_NOT_LOADED;
    }
    if (l->count > 1) {
        *status = "several-loaded";
        return RC_MISMATCH;
    }
    if (l->bad_uuid || l->nuuid != 1) {
        *status = "loaded-uuid-unreadable";
        return RC_ERROR;
    }
    if (memcmp(l->uuids[0], pin, 16) != 0) {
        *status = "mismatch";
        return RC_MISMATCH;
    }
    *status = "match";
    return RC_OK;
}

/* KextManagerCopyLoadedKextInfo is the in-process equivalent of `kmutil showloaded` and works without
 * root. It is not marked deprecated by the SDK this was written against; if a newer SDK deprecates
 * it, the -Werror build fails here and must be revisited rather than silenced. */
static bool query_loaded(struct loaded *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof *out);
    const void *keyvals[2] = {CFSTR("CFBundleIdentifier"), CFSTR("OSBundleUUID")};
    CFArrayRef keys = CFArrayCreate(NULL, keyvals, 2, &kCFTypeArrayCallBacks);
    if (!keys) {
        snprintf(err, errlen, "CFArrayCreate failed");
        return false;
    }
    CFDictionaryRef info = KextManagerCopyLoadedKextInfo(NULL, keys);
    CFRelease(keys);
    if (!info) {
        snprintf(err, errlen, "KextManagerCopyLoadedKextInfo returned NULL");
        return false;
    }
    CFIndex n = CFDictionaryGetCount(info);
    if (n <= 0) {
        CFRelease(info);
        snprintf(err, errlen, "KextManagerCopyLoadedKextInfo returned no kexts (query unusable)");
        return false;
    }
    const void **vals = calloc((size_t)n, sizeof *vals);
    if (!vals) {
        CFRelease(info);
        snprintf(err, errlen, "out of memory");
        return false;
    }
    CFDictionaryGetKeysAndValues(info, NULL, vals);
    for (CFIndex i = 0; i < n; i++) {
        if (!vals[i] || CFGetTypeID(vals[i]) != CFDictionaryGetTypeID()) {
            continue;
        }
        CFDictionaryRef e = (CFDictionaryRef)vals[i];
        CFTypeRef id = CFDictionaryGetValue(e, CFSTR("CFBundleIdentifier"));
        if (!id || CFGetTypeID(id) != CFStringGetTypeID() || !CFEqual(id, CFSTR(BUNDLE_ID))) {
            continue;
        }
        out->count++;
        CFTypeRef u = CFDictionaryGetValue(e, CFSTR("OSBundleUUID"));
        if (u && CFGetTypeID(u) == CFDataGetTypeID() && CFDataGetLength((CFDataRef)u) == 16) {
            if (out->nuuid < LOADED_MAX) {
                CFDataGetBytes((CFDataRef)u, CFRangeMake(0, 16), out->uuids[out->nuuid]);
                out->nuuid++;
            }
        } else {
            out->bad_uuid = true;
        }
    }
    free(vals);
    CFRelease(info);
    return true;
}

static bool resolve_pin(const struct opts *o, uint8_t pin[16], char *src, size_t srclen, char *err, size_t errlen)
{
    if (o->have_uuid) {
        memcpy(pin, o->uuid, 16);
        snprintf(src, srclen, "uuid-flag");
        return true;
    }
    const char *path = o->provenance ? o->provenance : DEFAULT_PROVENANCE;
    char buf[PROV_MAX + 1];
    size_t len = 0;
    if (!read_file_limited(path, buf, sizeof buf, &len, err, errlen)) {
        return false;
    }
    struct provenance p;
    char perr[160];
    if (!prov_parse(buf, len, &p, perr, sizeof perr)) {
        snprintf(err, errlen, "%s: %s", path, perr);
        return false;
    }
    memcpy(pin, p.lc_uuid, 16);
    snprintf(src, srclen, "provenance:%s", path);
    return true;
}

/* Runs the identity check and emits the `identity` event. Returns the exit code. */
static int identity_gate(const struct opts *o, const char **status_out)
{
    uint8_t pin[16];
    char src[1100];
    char err[256];
    *status_out = "error";
    if (!resolve_pin(o, pin, src, sizeof src, err, sizeof err)) {
        eprintf_("pinned UUID unavailable: %s", err);
        *status_out = "pin-unavailable";
        return RC_ERROR;
    }
    struct loaded l;
    if (!query_loaded(&l, err, sizeof err)) {
        eprintf_("loaded-kext query failed: %s", err);
        *status_out = "query-failed";
        return RC_ERROR;
    }
    const char *status = "error";
    int rc = classify_identity(&l, pin, &status);

    struct jb j;
    char text[37];
    jb_event(&j, "identity");
    jb_kstr(&j, "bundle_identifier", BUNDLE_ID);
    jb_kstr(&j, "pin_source", src);
    uuid_to_text(pin, text);
    jb_kstr(&j, "pinned_uuid", text);
    jb_ku64(&j, "loaded_count", l.count);
    jb_key(&j, "loaded_uuids");
    jb_open(&j, '[');
    for (size_t i = 0; i < l.nuuid; i++) {
        uuid_to_text(l.uuids[i], text);
        jb_str(&j, text);
    }
    jb_close(&j, ']');
    jb_kstr(&j, "result", status);
    jb_ku64(&j, "exit", (uint64_t)rc);
    jb_emit(&j);
    if (rc == RC_ERROR) {
        eprintf_("loaded %s has no readable 16-byte OSBundleUUID", BUNDLE_ID);
    }
    *status_out = status;
    return rc;
}

static int cmd_identity(const struct opts *o)
{
    const char *status;
    int rc = identity_gate(o, &status);
    emit_summary("identity", status, rc, -1);
    return rc;
}

/* ------------------------------------------------------------------------------------------ */
/* IOKit service access                                                                        */
/* ------------------------------------------------------------------------------------------ */

struct svc {
    io_service_t obj;
    uint64_t id;
};

static void release_services(struct svc *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        IOObjectRelease(v[i].obj);
        v[i].obj = IO_OBJECT_NULL;
    }
}

/* Every registered gay_bowser_usbgadget service, optionally filtered to one registry entry ID. Only
 * services of that class can be returned: an arbitrary --entry-id never reaches a foreign driver. */
static kern_return_t collect_services(uint64_t want, struct svc *v, size_t cap, size_t *n_out)
{
    for (int attempt = 0; attempt < 4; attempt++) {
        CFMutableDictionaryRef match = IOServiceMatching(SERVICE_CLASS);
        if (!match) {
            return kIOReturnNoMemory;
        }
        io_iterator_t it = IO_OBJECT_NULL;
        kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, match, &it); /* consumes match */
        if (kr != KERN_SUCCESS) {
            return kr;
        }
        if (it == IO_OBJECT_NULL) {
            /* The class is not in the registry at all (kext not loaded): success with an empty set, no iterator. */
            *n_out = 0;
            return KERN_SUCCESS;
        }
        size_t n = 0;
        kern_return_t fail = KERN_SUCCESS;
        io_service_t s;
        while ((s = IOIteratorNext(it)) != IO_OBJECT_NULL) {
            uint64_t id = 0;
            kern_return_t k2 = IORegistryEntryGetRegistryEntryID(s, &id);
            if (k2 != KERN_SUCCESS) {
                fail = k2;
                IOObjectRelease(s);
                continue;
            }
            if (want != 0 && id != want) {
                IOObjectRelease(s);
                continue;
            }
            if (n == cap) {
                fail = kIOReturnNoSpace;
                IOObjectRelease(s);
                continue;
            }
            v[n].obj = s;
            v[n].id = id;
            n++;
        }
        bool valid = IOIteratorIsValid(it);
        IOObjectRelease(it);
        if (fail != KERN_SUCCESS || !valid) {
            release_services(v, n);
            if (fail != KERN_SUCCESS) {
                return fail;
            }
            continue; /* registry changed during iteration: restart */
        }
        *n_out = n;
        return KERN_SUCCESS;
    }
    return kIOReturnNotReady;
}

/* Children of the service in the IOService plane: total, and those of the user-client class. */
static kern_return_t count_children(io_registry_entry_t svc, uint32_t *uc, uint32_t *total)
{
    for (int attempt = 0; attempt < 8; attempt++) {
        io_iterator_t it = IO_OBJECT_NULL;
        kern_return_t kr = IORegistryEntryGetChildIterator(svc, kIOServicePlane, &it);
        if (kr != KERN_SUCCESS) {
            return kr;
        }
        uint32_t u = 0;
        uint32_t t = 0;
        io_object_t child;
        while ((child = IOIteratorNext(it)) != IO_OBJECT_NULL) {
            io_name_t cls = "";
            if (IOObjectGetClass(child, cls) == KERN_SUCCESS && strcmp(cls, USERCLIENT_CLASS) == 0) {
                u++;
            }
            t++;
            IOObjectRelease(child);
        }
        bool valid = IOIteratorIsValid(it);
        IOObjectRelease(it);
        if (valid) {
            *uc = u;
            if (total) {
                *total = t;
            }
            return KERN_SUCCESS;
        }
    }
    return kIOReturnNotReady;
}

static uint64_t now_ns(void)
{
    return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
}

static void sleep_ms(uint64_t ms)
{
    struct timespec ts = {(time_t)(ms / 1000), (long)((ms % 1000) * 1000000ull)};
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
    }
}

static bool configuration_published(io_service_t s)
{
    CFTypeRef p = IORegistryEntryCreateCFProperty(s, CFSTR("PublishConfiguration"), kCFAllocatorDefault, 0);
    if (!p) {
        return false;
    }
    CFRelease(p);
    return true;
}

static void jb_entry_name(struct jb *j, const char *key, io_registry_entry_t e, bool location)
{
    io_name_t buf = "";
    kern_return_t kr = location ? IORegistryEntryGetLocationInPlane(e, kIOServicePlane, buf)
                                : IORegistryEntryGetNameInPlane(e, kIOServicePlane, buf);
    jb_key(j, key);
    if (kr == KERN_SUCCESS) {
        jb_str(j, buf);
    } else {
        jb_null(j);
    }
}

static int cmd_inventory(void)
{
    struct svc v[SVC_MAX];
    size_t n = 0;
    kern_return_t kr = collect_services(0, v, SVC_MAX, &n);
    if (kr != KERN_SUCCESS) {
        eprintf_("service enumeration failed: 0x%08x (%s)", (uint32_t)kr, kr_name((uint32_t)kr));
        emit_summary("inventory", "enumeration-failed", RC_ERROR, -1);
        return RC_ERROR;
    }
    for (size_t i = 0; i < n; i++) {
        struct jb j;
        io_name_t cls = "";
        uint32_t busy = 0;
        uint32_t uc = 0;
        uint32_t total = 0;
        jb_event(&j, "service");
        jb_ku64(&j, "entry_id", v[i].id);
        if (IOObjectGetClass(v[i].obj, cls) == KERN_SUCCESS) {
            jb_kstr(&j, "class", cls);
        }
        jb_entry_name(&j, "name", v[i].obj, false);
        jb_entry_name(&j, "location", v[i].obj, true);
        io_registry_entry_t parent = IO_OBJECT_NULL;
        if (IORegistryEntryGetParentEntry(v[i].obj, kIOServicePlane, &parent) == KERN_SUCCESS) {
            io_name_t pcls = "";
            jb_key(&j, "provider");
            jb_open(&j, '{');
            if (IOObjectGetClass(parent, pcls) == KERN_SUCCESS) {
                jb_kstr(&j, "class", pcls);
            }
            jb_entry_name(&j, "name", parent, false);
            jb_entry_name(&j, "location", parent, true);
            jb_close(&j, '}');
            IOObjectRelease(parent);
        } else {
            jb_key(&j, "provider");
            jb_null(&j);
        }
        if (IOServiceGetBusyState(v[i].obj, &busy) == KERN_SUCCESS) {
            jb_ku64(&j, "busy_state", busy);
            jb_kbool(&j, "busy", busy != 0);
        }
        if (count_children(v[i].obj, &uc, &total) == KERN_SUCCESS) {
            jb_ku64(&j, "userclient_children", uc);
            jb_ku64(&j, "children", total);
        }
        jb_kbool(&j, "configuration_published", configuration_published(v[i].obj));
        jb_emit(&j);
    }
    release_services(v, n);
    int rc = n > 0 ? RC_OK : RC_NO_SERVICE;
    emit_summary("inventory", n > 0 ? "ok" : "no-service", rc, (int64_t)n);
    return rc;
}

/* ------------------------------------------------------------------------------------------ */
/* Guarded commands: identity gate, then service selection                                     */
/* ------------------------------------------------------------------------------------------ */

typedef int (*svc_fn)(const struct svc *s, const struct opts *o);

static int run_guarded(const char *command, const struct opts *o, svc_fn fn, const char *fail_status)
{
    if (geteuid() == 0) {
        eprintf_("%s refuses to run as root: the S3 boundary evidence must come from an unprivileged caller", command);
        emit_summary(command, "refused-root", RC_ERROR, -1);
        return RC_ERROR;
    }
    const char *idstatus;
    int rc = identity_gate(o, &idstatus);
    if (rc != RC_OK) {
        eprintf_("%s refused: loaded driver identity check failed (%s); nothing was opened or written", command,
                 idstatus);
        struct jb j;
        jb_event(&j, "summary");
        jb_kstr(&j, "command", command);
        jb_kstr(&j, "status", "refused-identity");
        jb_kstr(&j, "identity_status", idstatus);
        jb_kbool(&j, "ok", false);
        jb_ku64(&j, "exit", (uint64_t)rc);
        jb_emit(&j);
        return rc;
    }

    struct svc v[SVC_MAX];
    size_t n = 0;
    kern_return_t kr = collect_services(o->entry_id, v, SVC_MAX, &n);
    if (kr != KERN_SUCCESS) {
        eprintf_("service enumeration failed: 0x%08x (%s)", (uint32_t)kr, kr_name((uint32_t)kr));
        emit_summary(command, "enumeration-failed", RC_ERROR, -1);
        return RC_ERROR;
    }
    if (n == 0) {
        eprintf_("%s: no gay_bowser_usbgadget service%s", command, o->entry_id ? " with that --entry-id" : "");
        emit_summary(command, "no-service", RC_NO_SERVICE, 0);
        return RC_NO_SERVICE;
    }
    rc = RC_OK;
    for (size_t i = 0; i < n; i++) {
        int r = fn(&v[i], o);
        if (rc == RC_OK) {
            rc = r;
        }
    }
    release_services(v, n);
    emit_summary(command, rc == RC_OK ? "ok" : fail_status, rc, (int64_t)n);
    return rc;
}

/* ------------------------------------------------------------------------------------------ */
/* open-close                                                                                  */
/* ------------------------------------------------------------------------------------------ */

static int open_close_one(const struct svc *s, const struct opts *o)
{
    uint32_t baseline = 0;
    kern_return_t kr = count_children(s->obj, &baseline, NULL);
    if (kr != KERN_SUCCESS) {
        eprintf_("entry %llu: cannot read baseline user-client count: 0x%08x", (unsigned long long)s->id,
                 (uint32_t)kr);
        return RC_ERROR;
    }
    uint32_t max = baseline;
    uint64_t sample_errors = 0;
    struct hist open_h = {{0}, {0}, 0, 0};
    struct hist close_h = {{0}, {0}, 0, 0};
    uint64_t t_start = now_ns();

    for (uint64_t i = 0; i < o->iterations; i++) {
        io_connect_t conn = IO_OBJECT_NULL;
        uint32_t cur = 0;
        kr = IOServiceOpen(s->obj, mach_task_self(), 0, &conn);
        hist_add(&open_h, (uint32_t)kr);
        if (kr == KERN_SUCCESS) {
            if (count_children(s->obj, &cur, NULL) == KERN_SUCCESS) {
                if (cur > max) {
                    max = cur;
                }
            } else {
                sample_errors++;
            }
            kern_return_t kc = IOServiceClose(conn);
            hist_add(&close_h, (uint32_t)kc);
        }
        if (count_children(s->obj, &cur, NULL) == KERN_SUCCESS) {
            if (cur > max) {
                max = cur;
            }
        } else {
            sample_errors++;
        }
    }
    uint64_t loop_ms = (now_ns() - t_start) / 1000000ull;

    /* Termination of a closed user client is asynchronous: poll until the count is back at baseline. */
    uint32_t final = 0;
    uint64_t settle_start = now_ns();
    uint64_t settle_elapsed = 0;
    bool settled = false;
    for (;;) {
        if (count_children(s->obj, &final, NULL) != KERN_SUCCESS) {
            sample_errors++;
        } else if (final == baseline) {
            settled = true;
        }
        settle_elapsed = (now_ns() - settle_start) / 1000000ull;
        if (settled || settle_elapsed >= o->settle_ms) {
            break;
        }
        uint64_t left = o->settle_ms - settle_elapsed;
        sleep_ms(left < 10 ? left : 10);
    }

    uint64_t opens_ok = hist_of(&open_h, (uint32_t)KERN_SUCCESS);
    uint64_t closes_ok = hist_of(&close_h, (uint32_t)KERN_SUCCESS);
    bool ok = settled && final == baseline && opens_ok == o->iterations && closes_ok == o->iterations &&
              sample_errors == 0 && hist_total(&open_h) == o->iterations;

    struct jb j;
    jb_event(&j, "open-close");
    jb_ku64(&j, "entry_id", s->id);
    jb_ku64(&j, "iterations", o->iterations);
    jb_ku64(&j, "baseline", baseline);
    jb_ku64(&j, "max", max);
    jb_ku64(&j, "final", final);
    jb_kbool(&j, "settled", settled);
    jb_ku64(&j, "settle_ms_elapsed", settle_elapsed);
    jb_ku64(&j, "settle_ms_limit", o->settle_ms);
    jb_ku64(&j, "loop_ms", loop_ms);
    jb_ku64(&j, "sample_errors", sample_errors);
    jb_hist(&j, "open_histogram", &open_h);
    jb_hist(&j, "close_histogram", &close_h);
    jb_kbool(&j, "ok", ok);
    jb_emit(&j);
    return ok ? RC_OK : RC_LEAK;
}

static int cmd_open_close(const struct opts *o)
{
    return run_guarded("open-close", o, open_close_one, "leaked-or-unsettled");
}

/* ------------------------------------------------------------------------------------------ */
/* poke                                                                                        */
/* ------------------------------------------------------------------------------------------ */

struct poke_ctx {
    io_service_t svc;
    CFDictionaryRef props;
    uint64_t iterations;
    atomic_bool go;
    atomic_bool stop;
};

struct poke_thread {
    struct poke_ctx *ctx;
    pthread_t tid;
    bool hung; /* main thread only */
    _Atomic uint64_t call_start; /* 0 = not inside a call */
    atomic_bool done;
    uint64_t calls; /* worker-owned until joined */
    uint64_t max_ns;
    struct hist hist;
};

static void *poke_main(void *arg)
{
    struct poke_thread *t = arg;
    struct poke_ctx *c = t->ctx;
    while (!atomic_load(&c->go)) {
        sched_yield();
    }
    for (uint64_t i = 0; i < c->iterations && !atomic_load(&c->stop); i++) {
        uint64_t t0 = now_ns();
        atomic_store(&t->call_start, t0);
        kern_return_t kr = IORegistryEntrySetCFProperties(c->svc, c->props);
        uint64_t t1 = now_ns();
        atomic_store(&t->call_start, 0);
        hist_add(&t->hist, (uint32_t)kr);
        t->calls++;
        if (t1 - t0 > t->max_ns) {
            t->max_ns = t1 - t0;
        }
    }
    atomic_store(&t->done, true);
    return NULL;
}

static int poke_one(const struct svc *s, const struct opts *o)
{
    const void *k[1] = {CFSTR("Poke")};
    const void *v[1] = {CFSTR("Poke")};
    CFDictionaryRef props =
        CFDictionaryCreate(NULL, k, v, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    struct poke_ctx *ctx = calloc(1, sizeof *ctx);
    struct poke_thread *th = calloc((size_t)o->threads, sizeof *th);
    if (!props || !ctx || !th) {
        eprintf_("out of memory");
        if (props) {
            CFRelease(props);
        }
        free(ctx);
        free(th);
        return RC_ERROR;
    }
    ctx->svc = s->obj;
    ctx->props = props;
    ctx->iterations = o->iterations;
    atomic_init(&ctx->go, false);
    atomic_init(&ctx->stop, false);
    bool published = configuration_published(s->obj);

    size_t nthreads = (size_t)o->threads;
    size_t created = 0;
    bool create_failed = false;
    for (size_t i = 0; i < nthreads; i++) {
        th[i].ctx = ctx;
        atomic_init(&th[i].call_start, 0);
        atomic_init(&th[i].done, false);
        if (pthread_create(&th[i].tid, NULL, poke_main, &th[i]) != 0) {
            create_failed = true;
            break;
        }
        created++;
    }
    if (create_failed) {
        eprintf_("pthread_create failed after %zu threads", created);
        atomic_store(&ctx->stop, true);
        atomic_store(&ctx->go, true);
        for (size_t i = 0; i < created; i++) {
            pthread_join(th[i].tid, NULL);
        }
        CFRelease(props);
        free(ctx);
        free(th);
        return RC_ERROR;
    }

    uint64_t timeout_ns = o->call_timeout_ms * 1000000ull;
    uint64_t poll_ms = o->call_timeout_ms / 4;
    poll_ms = poll_ms < 1 ? 1 : (poll_ms > 20 ? 20 : poll_ms);
    uint64_t t_start = now_ns();
    uint64_t hang_at = 0;
    uint64_t hung_calls = 0;
    atomic_store(&ctx->go, true);

    for (;;) {
        uint64_t now = now_ns();
        size_t finished = 0;
        for (size_t i = 0; i < nthreads; i++) {
            if (atomic_load(&th[i].done)) {
                finished++;
                continue;
            }
            uint64_t cs = atomic_load(&th[i].call_start);
            if (cs != 0 && now > cs && now - cs > timeout_ns && !th[i].hung) {
                th[i].hung = true;
                hung_calls++;
                if (hang_at == 0) {
                    hang_at = now;
                }
                struct jb j;
                jb_event(&j, "hang");
                jb_ku64(&j, "entry_id", s->id);
                jb_ku64(&j, "thread", i);
                jb_ku64(&j, "elapsed_ms", (now - cs) / 1000000ull);
                jb_ku64(&j, "call_timeout_ms", o->call_timeout_ms);
                jb_emit(&j);
                atomic_store(&ctx->stop, true);
            }
        }
        if (finished == nthreads) {
            break;
        }
        if (hang_at != 0 && now - hang_at > timeout_ns) {
            /* A call is still blocked a full timeout after being flagged: threads cannot be cancelled out of
             * the kernel, so report and exit without joining. Per-thread histograms are not read (racy). */
            struct jb j;
            jb_event(&j, "poke");
            jb_ku64(&j, "entry_id", s->id);
            jb_ku64(&j, "iterations", o->iterations);
            jb_ku64(&j, "threads", o->threads);
            jb_ku64(&j, "stuck_threads", nthreads - finished);
            jb_ku64(&j, "hung_calls", hung_calls);
            jb_kbool(&j, "ok", false);
            jb_emit(&j);
            eprintf_("poke: %zu thread(s) still blocked in IORegistryEntrySetCFProperties; exiting without join",
                     nthreads - finished);
            emit_summary("poke", "hang", RC_HANG, -1);
            _exit(RC_HANG);
        }
        sleep_ms(poll_ms);
    }

    struct hist total = {{0}, {0}, 0, 0};
    uint64_t calls = 0;
    uint64_t max_ns = 0;
    for (size_t i = 0; i < nthreads; i++) {
        pthread_join(th[i].tid, NULL);
        hist_merge(&total, &th[i].hist);
        calls += th[i].calls;
        if (th[i].max_ns > max_ns) {
            max_ns = th[i].max_ns;
        }
    }
    uint64_t wall_ms = (now_ns() - t_start) / 1000000ull;
    uint64_t expected = o->iterations * o->threads;
    uint64_t succ = hist_of(&total, (uint32_t)KERN_SUCCESS);
    bool ok = hung_calls == 0 && calls == expected && succ == expected && total.overflow == 0;

    struct jb j;
    jb_event(&j, "poke");
    jb_ku64(&j, "entry_id", s->id);
    jb_ku64(&j, "iterations", o->iterations);
    jb_ku64(&j, "threads", o->threads);
    jb_ku64(&j, "calls", calls);
    jb_ku64(&j, "calls_expected", expected);
    jb_ku64(&j, "hung_calls", hung_calls);
    jb_ku64(&j, "call_timeout_ms", o->call_timeout_ms);
    jb_ku64(&j, "max_call_us", max_ns / 1000ull);
    jb_ku64(&j, "wall_ms", wall_ms);
    jb_kbool(&j, "configuration_published", published);
    jb_hist(&j, "histogram", &total);
    jb_kbool(&j, "ok", ok);
    jb_emit(&j);

    CFRelease(props);
    free(ctx);
    free(th);
    return ok ? RC_OK : RC_HANG;
}

static int cmd_poke(const struct opts *o)
{
    return run_guarded("poke", o, poke_one, "hang-or-unexpected-error");
}

/* ------------------------------------------------------------------------------------------ */
/* reject                                                                                      */
/* ------------------------------------------------------------------------------------------ */

static CF_RETURNS_RETAINED CFTypeRef make_dict(size_t n, const void **keys, const void **vals)
{
    return CFDictionaryCreate(NULL, keys, vals, (CFIndex)n, &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
}

static CF_RETURNS_RETAINED CFTypeRef mk_unknown_key(void)
{
    const void *k[1] = {CFSTR("S3ProbeUnknownKey")};
    const void *v[1] = {CFSTR("x")};
    return make_dict(1, k, v);
}

static CF_RETURNS_RETAINED CFTypeRef mk_poke_number(void)
{
    int32_t one = 1;
    CFNumberRef num = CFNumberCreate(NULL, kCFNumberSInt32Type, &one);
    if (!num) {
        return NULL;
    }
    const void *k[1] = {CFSTR("Poke")};
    const void *v[1] = {num};
    CFTypeRef d = make_dict(1, k, v);
    CFRelease(num);
    return d;
}

static CF_RETURNS_RETAINED CFTypeRef mk_publish_string(void)
{
    const void *k[1] = {CFSTR("PublishConfiguration")};
    const void *v[1] = {CFSTR("not-a-dictionary")};
    return make_dict(1, k, v);
}

static CF_RETURNS_RETAINED CFTypeRef mk_array(void)
{
    const void *v[1] = {CFSTR("Poke")};
    return CFArrayCreate(NULL, v, 1, &kCFTypeArrayCallBacks);
}

static CF_RETURNS_RETAINED CFTypeRef mk_string(void)
{
    return CFStringCreateCopy(NULL, CFSTR("Poke"));
}

static CF_RETURNS_RETAINED CFTypeRef mk_mixed(void)
{
    const void *k[2] = {CFSTR("Poke"), CFSTR("S3ProbeUnknownKey")};
    const void *v[2] = {CFSTR("Poke"), CFSTR("x")};
    return make_dict(2, k, v);
}

struct reject_case {
    const char *name;
    CFTypeRef (*make)(void);
};

static const struct reject_case REJECT_CASES[] = {
    {"unknown-key", mk_unknown_key},
    {"poke-with-number", mk_poke_number},
    {"publish-configuration-with-string", mk_publish_string},
    {"non-dictionary-array", mk_array},
    {"non-dictionary-string", mk_string},
    {"valid-poke-plus-unknown-key", mk_mixed},
};

/* kext setProperties() returns kIOReturnBadArgument for every one of these (usbgadget.cpp). */
#define REJECT_EXPECTED ((uint32_t)kIOReturnBadArgument)

static int reject_one(const struct svc *s, const struct opts *o)
{
    (void)o;
    int rc = RC_OK;
    uint64_t refused = 0;
    uint64_t expected_match = 0;
    uint64_t accepted_n = 0;
    for (size_t i = 0; i < sizeof REJECT_CASES / sizeof REJECT_CASES[0]; i++) {
        CFTypeRef obj = REJECT_CASES[i].make();
        if (!obj) {
            eprintf_("cannot build reject case '%s'", REJECT_CASES[i].name);
            return RC_ERROR;
        }
        kern_return_t kr = IORegistryEntrySetCFProperties(s->obj, obj);
        CFRelease(obj);
        bool accepted = kr == KERN_SUCCESS;
        struct jb j;
        jb_event(&j, "reject");
        jb_ku64(&j, "entry_id", s->id);
        jb_kstr(&j, "case", REJECT_CASES[i].name);
        jb_khex32(&j, "kr", (uint32_t)kr);
        jb_kstr(&j, "name", kr_name((uint32_t)kr));
        jb_khex32(&j, "expected_kr", REJECT_EXPECTED);
        jb_kbool(&j, "refused", !accepted);
        jb_kbool(&j, "expected_match", (uint32_t)kr == REJECT_EXPECTED);
        jb_emit(&j);
        if (accepted) {
            accepted_n++;
            rc = RC_ACCEPTED;
        } else {
            refused++;
        }
        if ((uint32_t)kr == REJECT_EXPECTED) {
            expected_match++;
        }
    }
    struct jb r;
    jb_event(&r, "reject-result");
    jb_ku64(&r, "entry_id", s->id);
    jb_ku64(&r, "cases", sizeof REJECT_CASES / sizeof REJECT_CASES[0]);
    jb_ku64(&r, "refused", refused);
    jb_ku64(&r, "accepted", accepted_n);
    jb_ku64(&r, "expected_code_matches", expected_match);
    jb_kbool(&r, "ok", accepted_n == 0);
    jb_emit(&r);
    return rc;
}

static int cmd_reject(const struct opts *o)
{
    return run_guarded("reject", o, reject_one, "accepted-invalid-input");
}

/* ------------------------------------------------------------------------------------------ */
/* self-test (no IOKit calls)                                                                  */
/* ------------------------------------------------------------------------------------------ */

static unsigned g_pass;
static unsigned g_fail;

static void check(bool cond, const char *name)
{
    struct jb j;
    jb_event(&j, "test");
    jb_kstr(&j, "name", name);
    jb_kbool(&j, "pass", cond);
    jb_emit(&j);
    if (cond) {
        g_pass++;
    } else {
        g_fail++;
    }
}

static const char GOOD_PROV[] =
    "format=mac2jb-bundled-kext-v1\n"
    "bundle_identifier=gay.bowser.usbgadget\n"
    "executable_sha256=de79702967e272694568d6545f4e131bfcf0b21509c1cc3aab8c4c4c572674c5\n"
    "info_plist_sha256=a4ca368ce107273aaf008a8dd68d1de898eb9889c5efc6e56ea76601912ce0bd\n"
    "lc_uuid=CF8E2A1A-9710-3430-998D-21A0E845D8B2\n"
    "source_tree_sha256=8987e0c90680e7a1f57e646c0cd8a9a339bced3cf737fec4a37f45e5d09a3e11\n"
    "source_commit=2f1b6db360756872b8aa03b3078c5709610adf5f\n"
    "xcode_build=27B52\n"
    "sdk_build=26B118\n";

static bool prov_ok(const char *text)
{
    struct provenance p;
    char err[160];
    return prov_parse(text, strlen(text), &p, err, sizeof err);
}

/* Replace the first occurrence of `from` in GOOD_PROV with `to` and parse. */
static bool prov_edit_ok(const char *from, const char *to)
{
    char buf[sizeof GOOD_PROV + 64];
    const char *at = strstr(GOOD_PROV, from);
    if (!at) {
        return true; /* a broken test must not look like a passing negative case */
    }
    size_t head = (size_t)(at - GOOD_PROV);
    int n = snprintf(buf, sizeof buf, "%.*s%s%s", (int)head, GOOD_PROV, to, at + strlen(from));
    if (n < 0 || (size_t)n >= sizeof buf) {
        return true;
    }
    return prov_ok(buf);
}

static bool args_parse(const char *cmdname, const char *line, struct opts *o)
{
    const struct cmddef *def = find_cmd(cmdname);
    char copy[256];
    const char *argv[24];
    int argc = 0;
    if (!def || strlen(line) >= sizeof copy) {
        return false;
    }
    strcpy(copy, line);
    char *save = NULL;
    for (char *tok = strtok_r(copy, " ", &save); tok && argc < 24; tok = strtok_r(NULL, " ", &save)) {
        argv[argc++] = tok;
    }
    char err[128];
    return parse_opts(def, argc, argv, o, err, sizeof err);
}

static bool args_ok(const char *cmdname, const char *line)
{
    struct opts o;
    return args_parse(cmdname, line, &o);
}

static void selftest_provenance(void)
{
    struct provenance p;
    char err[160];
    bool good = prov_parse(GOOD_PROV, strlen(GOOD_PROV), &p, err, sizeof err);
    check(good, "provenance: contract example parses");
    check(good && p.lc_uuid[0] == 0xCF && p.lc_uuid[1] == 0x8E && p.lc_uuid[15] == 0xB2,
          "provenance: lc_uuid bytes decoded");
    check(!prov_parse("", 0, &p, err, sizeof err), "provenance: empty file rejected");
    {
        char text[sizeof GOOD_PROV];
        memcpy(text, GOOD_PROV, sizeof GOOD_PROV);
        check(!prov_parse(text, sizeof GOOD_PROV, &p, err, sizeof err), "provenance: embedded NUL rejected");
    }
    {
        char text[sizeof GOOD_PROV];
        memcpy(text, GOOD_PROV, sizeof GOOD_PROV);
        text[strlen(text) - 1] = '\0';
        check(!prov_ok(text), "provenance: missing final LF rejected");
    }
    check(!prov_edit_ok("format=mac2jb-bundled-kext-v1\n", "format=mac2jb-bundled-kext-v1\r\n"),
          "provenance: CRLF rejected");
    check(!prov_edit_ok("format=mac2jb-bundled-kext-v1", "format=other"), "provenance: wrong format value rejected");
    check(!prov_edit_ok("bundle_identifier=gay.bowser.usbgadget", "bundle_identifier=com.example.other"),
          "provenance: wrong bundle identifier rejected");
    check(!prov_edit_ok("sdk_build=26B118\n", "sdk_build=26B118\nsdk_build=26B118\n"),
          "provenance: duplicate key rejected");
    check(!prov_edit_ok("lc_uuid=", "lc_uuid=CF8E2A1A-9710-3430-998D-21A0E845D8B2\nlc_uuid="),
          "provenance: duplicate lc_uuid rejected");
    check(!prov_edit_ok("sdk_build=26B118\n", "sdk_build=26B118\nextra=1\n"), "provenance: unknown extra key rejected");
    check(!prov_edit_ok("xcode_build=27B52\nsdk_build=26B118\n", "sdk_build=26B118\nxcode_build=27B52\n"),
          "provenance: out-of-order keys rejected");
    check(!prov_edit_ok("sdk_build=26B118\n", ""), "provenance: missing last key rejected");
    check(!prov_edit_ok("format=mac2jb-bundled-kext-v1\n", ""), "provenance: missing first key rejected");
    check(!prov_edit_ok("xcode_build=27B52\n", "xcode_build\n"), "provenance: line without '=' rejected");
    check(!prov_edit_ok("xcode_build=27B52\n", "\nxcode_build=27B52\n"), "provenance: blank line rejected");
    check(!prov_edit_ok("lc_uuid=CF8E2A1A", "lc_uuid=cf8e2a1a"), "provenance: lowercase lc_uuid rejected");
    check(!prov_edit_ok("CF8E2A1A-9710-3430-998D-21A0E845D8B2", "CF8E2A1A-9710-3430-998D-21A0E845D8B"),
          "provenance: short lc_uuid rejected");
    check(!prov_edit_ok("CF8E2A1A-9710-3430-998D-21A0E845D8B2", "CF8E2A1A97103430998D21A0E845D8B2XXXX"),
          "provenance: undashed lc_uuid rejected");
    check(!prov_edit_ok("CF8E2A1A-9710-3430-998D-21A0E845D8B2", "CF8E2A1A-9710-3430-998D-21A0E845D8BG"),
          "provenance: non-hex lc_uuid rejected");
    check(!prov_edit_ok("lc_uuid=CF8E2A1A-9710-3430-998D-21A0E845D8B2", "lc_uuid="), "provenance: empty lc_uuid rejected");
    check(!prov_edit_ok("lc_uuid=CF8E2A1A-9710-3430-998D-21A0E845D8B2", "lc_uuid==CF8E2A1A-9710-3430-998D-21A0E845D8B"),
          "provenance: value starting with '=' rejected");
    check(!prov_edit_ok("de79702967e272694568d6545f4e131bfcf0b21509c1cc3aab8c4c4c572674c5",
                        "de79702967e272694568d6545f4e131bfcf0b21509c1cc3aab8c4c4c572674c"),
          "provenance: short sha256 rejected");
    check(!prov_edit_ok("a4ca368ce107273aaf008a8dd68d1de898eb9889c5efc6e56ea76601912ce0bd",
                        "A4CA368CE107273AAF008A8DD68D1DE898EB9889C5EFC6E56EA76601912CE0BD"),
          "provenance: uppercase sha256 rejected");
    check(!prov_edit_ok("2f1b6db360756872b8aa03b3078c5709610adf5f", "2f1b6db360756872b8aa03b3078c5709610adf5"),
          "provenance: short source_commit rejected");
    check(!prov_edit_ok("xcode_build=27B52", "xcode_build=27B52 "), "provenance: space in build token rejected");
    check(!prov_edit_ok("xcode_build=27B52", "xcode_build="), "provenance: empty build token rejected");
}

static void selftest_uuid_numbers(void)
{
    uint8_t u[16];
    char text[37];
    const char *s = "CF8E2A1A-9710-3430-998D-21A0E845D8B2";
    check(uuid_parse_text(s, strlen(s), true, u), "uuid: uppercase parses");
    uuid_to_text(u, text);
    check(strcmp(text, s) == 0, "uuid: format round-trips");
    const char *lower = "cf8e2a1a-9710-3430-998d-21a0e845d8b2";
    check(uuid_parse_text(lower, strlen(lower), false, u), "uuid: lowercase accepted when not upper-only");
    uuid_to_text(u, text);
    check(strcmp(text, s) == 0, "uuid: lowercase input normalizes to uppercase");
    check(!uuid_parse_text(lower, strlen(lower), true, u), "uuid: lowercase rejected when upper-only");
    check(!uuid_parse_text("", 0, false, u), "uuid: empty rejected");
    check(!uuid_parse_text("CF8E2A1A-9710-3430-998D-21A0E845D8B2-", 37, false, u), "uuid: trailing dash rejected");
    check(!uuid_parse_text("CF8E2A1A_9710-3430-998D-21A0E845D8B2", 36, false, u), "uuid: wrong separator rejected");
    check(!uuid_parse_text("CF8E2A1A-9710-3430-998D-21A0E845D8B-", 36, false, u), "uuid: separator in last group rejected");
    check(!uuid_parse_text("CF8E2A1A-9710-3430-998D-21A0E845D8BZ", 36, false, u), "uuid: non-hex rejected");

    uint64_t v = 0;
    check(parse_dec("1", 1, 100000, &v) && v == 1, "number: lower bound accepted");
    check(parse_dec("100000", 1, 100000, &v) && v == 100000, "number: upper bound accepted");
    check(!parse_dec("0", 1, 100000, &v), "number: below lower bound rejected");
    check(!parse_dec("100001", 1, 100000, &v), "number: above upper bound rejected");
    check(!parse_dec("", 0, 10, &v), "number: empty rejected");
    check(!parse_dec("-1", 0, 10, &v), "number: sign rejected");
    check(!parse_dec("+1", 0, 10, &v), "number: plus rejected");
    check(!parse_dec(" 1", 0, 10, &v), "number: leading space rejected");
    check(!parse_dec("1 ", 0, 10, &v), "number: trailing space rejected");
    check(!parse_dec("0x1", 0, 10, &v), "number: hex rejected");
    check(!parse_dec("1e3", 0, 10000, &v), "number: exponent rejected");
    check(!parse_dec("99999999999999999999999", 0, UINT64_MAX, &v), "number: overflow rejected");
    check(!parse_dec("18446744073709551616", 0, UINT64_MAX, &v), "number: 2^64 rejected");
    check(parse_dec("18446744073709551615", 0, UINT64_MAX, &v) && v == UINT64_MAX, "number: 2^64-1 accepted");
    check(parse_entry_id("42", &v) && v == 42, "entry-id: decimal accepted");
    check(parse_entry_id("0x10000abcd", &v) && v == 0x10000abcdull, "entry-id: hex accepted");
    check(!parse_entry_id("0", &v), "entry-id: zero rejected");
    check(!parse_entry_id("0x0", &v), "entry-id: hex zero rejected");
    check(!parse_entry_id("0x", &v), "entry-id: bare 0x rejected");
    check(!parse_entry_id("0xg1", &v), "entry-id: non-hex digit rejected");
    check(!parse_entry_id("0x10000000000000000", &v), "entry-id: 17 hex digits rejected");
    check(!parse_entry_id("abc", &v), "entry-id: letters rejected");
    check(!parse_entry_id("-1", &v), "entry-id: sign rejected");
}

static void selftest_args(void)
{
    struct opts o;
    check(args_parse("open-close", "--iterations 10", &o) && o.iterations == 10 && o.settle_ms == SETTLE_MS_DEFAULT &&
              o.entry_id == 0,
          "args: open-close minimal parses with defaults");
    check(args_parse("open-close", "--iterations 5 --entry-id 0x1f --settle-ms 0 --provenance /tmp/p", &o) &&
              o.entry_id == 0x1f && o.settle_ms == 0 && o.provenance && strcmp(o.provenance, "/tmp/p") == 0,
          "args: open-close full parses");
    check(args_parse("poke", "--iterations 3 --threads 64 --call-timeout-ms 600000", &o) && o.threads == 64 &&
              o.call_timeout_ms == 600000,
          "args: poke bounds accepted");
    check(args_parse("poke", "--threads 2 --iterations 3", &o) && o.call_timeout_ms == CALL_TIMEOUT_MS_DEFAULT,
          "args: poke default timeout");
    check(args_parse("identity", "--uuid cf8e2a1a-9710-3430-998d-21a0e845d8b2", &o) && o.have_uuid && o.uuid[0] == 0xCF,
          "args: identity --uuid parses");
    check(args_parse("reject", "", &o) && o.entry_id == 0, "args: reject without flags parses");
    check(args_parse("self-test", "", &o), "args: self-test without flags parses");

    check(!args_ok("open-close", ""), "args: open-close without --iterations rejected");
    check(!args_ok("poke", "--iterations 3"), "args: poke without --threads rejected");
    check(!args_ok("poke", "--threads 3"), "args: poke without --iterations rejected");
    check(!args_ok("open-close", "--iterations 0"), "args: iterations 0 rejected");
    check(!args_ok("open-close", "--iterations 100001"), "args: iterations 100001 rejected");
    check(!args_ok("open-close", "--iterations -1"), "args: negative iterations rejected");
    check(!args_ok("open-close", "--iterations 1x"), "args: iterations garbage rejected");
    check(!args_ok("poke", "--iterations 1 --threads 0"), "args: threads 0 rejected");
    check(!args_ok("poke", "--iterations 1 --threads 65"), "args: threads 65 rejected");
    check(!args_ok("open-close", "--iterations 1 --settle-ms 60001"), "args: settle-ms 60001 rejected");
    check(!args_ok("open-close", "--iterations 1 --settle-ms -1"), "args: negative settle-ms rejected");
    check(!args_ok("poke", "--iterations 1 --threads 1 --call-timeout-ms 0"), "args: call-timeout-ms 0 rejected");
    check(!args_ok("poke", "--iterations 1 --threads 1 --call-timeout-ms 600001"),
          "args: call-timeout-ms 600001 rejected");
    check(!args_ok("open-close", "--iterations 1 --bogus 1"), "args: unknown flag rejected");
    check(!args_ok("open-close", "--iterations 1 stray"), "args: positional argument rejected");
    check(!args_ok("open-close", "--iterations 1 --iterations 2"), "args: duplicate flag rejected");
    check(!args_ok("open-close", "--iterations"), "args: flag without value rejected");
    check(!args_ok("open-close", "--iterations --entry-id 1"), "args: flag value that is a flag rejected");
    check(!args_ok("inventory", "--iterations 1"), "args: flag not valid for inventory rejected");
    check(!args_ok("identity", "--iterations 1"), "args: iterations not valid for identity rejected");
    check(!args_ok("reject", "--threads 2"), "args: threads not valid for reject rejected");
    check(!args_ok("open-close", "--iterations 1 --provenance a --uuid CF8E2A1A-9710-3430-998D-21A0E845D8B2"),
          "args: provenance and uuid together rejected");
    check(!args_ok("identity", "--uuid not-a-uuid"), "args: malformed --uuid rejected");
    check(!args_ok("open-close", "--iterations 1 --entry-id 0"), "args: entry-id 0 rejected");
    check(!args_ok("open-close", "--iterations 1 --entry-id zz"), "args: malformed entry-id rejected");
    check(find_cmd("open-close") != NULL && find_cmd("nope") == NULL && find_cmd("") == NULL,
          "args: command lookup is exact");
}

static void selftest_classify_hist_json(void)
{
    uint8_t pin[16];
    uint8_t other[16];
    const char *st = NULL;
    uuid_parse_text("CF8E2A1A-9710-3430-998D-21A0E845D8B2", 36, true, pin);
    uuid_parse_text("124391F6-0CFF-32E0-8884-6F6360DF5D1C", 36, true, other);

    struct loaded l;
    memset(&l, 0, sizeof l);
    check(classify_identity(&l, pin, &st) == RC_NOT_LOADED && strcmp(st, "not-loaded") == 0,
          "identity: nothing loaded -> exit 2");
    l.count = 1;
    l.nuuid = 1;
    memcpy(l.uuids[0], pin, 16);
    check(classify_identity(&l, pin, &st) == RC_OK && strcmp(st, "match") == 0, "identity: pinned UUID -> exit 0");
    memcpy(l.uuids[0], other, 16);
    check(classify_identity(&l, pin, &st) == RC_MISMATCH && strcmp(st, "mismatch") == 0,
          "identity: other UUID (old upstream binary) -> exit 3");
    memcpy(l.uuids[0], pin, 16);
    l.uuids[0][15] ^= 1; /* one bit away from the pinned UUID */
    check(classify_identity(&l, pin, &st) == RC_MISMATCH, "identity: one-bit UUID difference -> exit 3");
    memcpy(l.uuids[0], pin, 16);
    l.count = 2;
    check(classify_identity(&l, pin, &st) == RC_MISMATCH && strcmp(st, "several-loaded") == 0,
          "identity: several loaded (even if one matches) -> exit 3");
    l.count = 1;
    l.bad_uuid = true;
    check(classify_identity(&l, pin, &st) == RC_ERROR, "identity: unreadable loaded UUID -> exit 1");

    struct hist h = {{0}, {0}, 0, 0};
    struct hist g = {{0}, {0}, 0, 0};
    hist_add(&h, 0);
    hist_add(&h, 0);
    hist_add(&h, (uint32_t)kIOReturnBadArgument);
    hist_add(&g, 0);
    hist_add(&g, (uint32_t)kIOReturnBusy);
    hist_merge(&h, &g);
    check(hist_of(&h, 0) == 3 && hist_of(&h, (uint32_t)kIOReturnBadArgument) == 1 &&
              hist_of(&h, (uint32_t)kIOReturnBusy) == 1 && hist_total(&h) == 5 && hist_of(&h, 99) == 0,
          "histogram: add and merge");
    struct hist full = {{0}, {0}, 0, 0};
    for (uint32_t i = 0; i < HIST_MAX + 3; i++) {
        hist_add(&full, i);
    }
    check(full.n == HIST_MAX && full.overflow == 3 && hist_total(&full) == HIST_MAX + 3,
          "histogram: overflow is counted, not dropped");
    check(strcmp(kr_name((uint32_t)kIOReturnBadArgument), "kIOReturnBadArgument") == 0 &&
              strcmp(kr_name(0), "success") == 0 && strcmp(kr_name(0x12345678), "unknown") == 0,
          "kr_name: known and unknown codes");

    struct jb j;
    jb_event(&j, "x");
    jb_kstr(&j, "s", "a\"b\\c\n\x01\xc3");
    jb_key(&j, "arr");
    jb_open(&j, '[');
    jb_u64(&j, 1);
    jb_bool(&j, false);
    jb_null(&j);
    jb_close(&j, ']');
    jb_close(&j, '}');
    check(!j.overflow &&
              strcmp(j.buf, "{\"event\":\"x\",\"s\":\"a\\\"b\\\\c\\u000a\\u0001\\u00c3\",\"arr\":[1,false,null]}") == 0,
          "json: escaping and separators");
    jb_event(&j, "big");
    for (int i = 0; i < 2000; i++) {
        jb_kstr(&j, "k", "0123456789");
    }
    check(j.overflow, "json: oversize line is detected, not truncated silently");
}

static int cmd_self_test(void)
{
    selftest_provenance();
    selftest_uuid_numbers();
    selftest_args();
    selftest_classify_hist_json();
    struct jb j;
    jb_event(&j, "summary");
    jb_kstr(&j, "command", "self-test");
    jb_kstr(&j, "status", g_fail == 0 ? "ok" : "failed");
    jb_kbool(&j, "ok", g_fail == 0);
    jb_ku64(&j, "exit", g_fail == 0 ? RC_OK : RC_ERROR);
    jb_ku64(&j, "passed", g_pass);
    jb_ku64(&j, "failed", g_fail);
    jb_emit(&j);
    return g_fail == 0 ? RC_OK : RC_ERROR;
}

/* ------------------------------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return RC_ERROR;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) {
        usage(stdout);
        return RC_OK;
    }
    const struct cmddef *def = find_cmd(argv[1]);
    if (!def) {
        eprintf_("unknown command '%s'", argv[1]);
        usage(stderr);
        return RC_ERROR;
    }
    struct opts o;
    char err[160];
    if (!parse_opts(def, argc - 2, (const char *const *)(argv + 2), &o, err, sizeof err)) {
        eprintf_("%s: %s", def->name, err);
        return RC_ERROR;
    }
    if (def->cmd == CMD_SELF_TEST) {
        return cmd_self_test();
    }
    emit_start(def->name);
    switch (def->cmd) {
    case CMD_IDENTITY: return cmd_identity(&o);
    case CMD_INVENTORY: return cmd_inventory();
    case CMD_OPEN_CLOSE: return cmd_open_close(&o);
    case CMD_POKE: return cmd_poke(&o);
    case CMD_REJECT: return cmd_reject(&o);
    default: return RC_ERROR;
    }
}
