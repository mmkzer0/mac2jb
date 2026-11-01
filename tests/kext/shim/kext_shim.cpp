#include "kext_shim.h"

#include <errno.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include <algorithm>

namespace kext_shim {

Stats g_stats;
Faults g_faults;
std::atomic<unsigned> g_sleep_cap_ms(2);

namespace {

struct OpFault {
    std::atomic<unsigned long> seen;
    std::atomic<unsigned long> fail_at;  // 0 = disarmed
    std::atomic<bool> sticky;
    std::atomic<bool> fired;
    std::atomic<int> fired_step;
};

OpFault g_ops[kOpCount];
std::atomic<int> g_step(0);
std::atomic<uint64_t> g_rng(0);
std::atomic<bool> g_quiescent(false);

const unsigned kTraceSize = 256;

// Relaxed atomics: the trace must not add happens-before edges that would hide races from TSan.
struct TraceEntry {
    std::atomic<unsigned long> seq;
    std::atomic<const char *> op;
    std::atomic<long> result;
    std::atomic<unsigned> thread;
};

TraceEntry g_trace[kTraceSize];
std::atomic<unsigned long> g_trace_seq(0);
std::atomic<unsigned> g_next_thread_id(1);
thread_local unsigned tls_thread_id = 0;
thread_local bool tls_is_worker = false;

unsigned current_thread_id() {
    if (tls_thread_id == 0) tls_thread_id = g_next_thread_id.fetch_add(1);
    return tls_thread_id;
}

}  // namespace

// Marks the calling thread as a kext-created worker (set by the thread trampoline).
void set_worker_thread(bool is_worker) { tls_is_worker = is_worker; }

static bool consume(std::atomic<bool> &flag) { return flag.exchange(false); }

void reset() {
    g_stats.threads_started = 0;
    g_stats.thread_deallocs = 0;
    g_stats.workers_running = 0;
    g_stats.violations = 0;
    g_stats.post_teardown_ops = 0;
    for (int i = 0; i < kOpCount; ++i) {
        g_ops[i].seen = 0;
        g_ops[i].fail_at = 0;
        g_ops[i].sticky = false;
        g_ops[i].fired = false;
        g_ops[i].fired_step = -1;
    }
    g_faults.alloc_mask = kAllocAllKinds;
    g_faults.super_init = false;
    g_faults.super_start = false;
    g_faults.super_init_with_task = false;
    g_faults.super_set_property = false;
    g_sleep_cap_ms = 2;
    g_step = 0;
    g_quiescent = false;
}

void arm_op_failure(Op op, unsigned long nth, bool sticky) {
    OpFault &f = g_ops[op];
    f.seen = 0;
    f.fired = false;
    f.fired_step = -1;
    f.sticky = sticky;
    f.fail_at = nth;
}

void disarm_op_failures() {
    for (int i = 0; i < kOpCount; ++i) g_ops[i].fail_at = 0;
}

bool op_failure_fired(Op op) { return g_ops[op].fired.load(); }
unsigned long op_count(Op op) { return g_ops[op].seen.load(); }
int op_failure_step(Op op) { return g_ops[op].fired_step.load(); }
void set_step(int step) { g_step = step; }

bool op_should_fail(Op op) {
    OpFault &f = g_ops[op];
    unsigned long n = ++f.seen;
    unsigned long at = f.fail_at.load();
    if (at == 0) return false;
    if (n == at || (f.sticky.load() && n > at)) {
        if (!f.fired.exchange(true)) f.fired_step = g_step.load();
        return true;
    }
    return false;
}

const char *op_name(Op op) {
    switch (op) {
        case kOpAlloc: return "alloc";
        case kOpLockAlloc: return "lock_alloc";
        case kOpThreadStart: return "thread_start";
        case kOpSetProperties: return "set_properties";
        default: return "?";
    }
}

void arm_alloc_failure(unsigned long nth, unsigned kind_mask, bool sticky) {
    g_faults.alloc_mask = kind_mask;
    arm_op_failure(kOpAlloc, nth, sticky);
}

void disarm_alloc_failure() { g_ops[kOpAlloc].fail_at = 0; }

bool alloc_failure_fired() { return op_failure_fired(kOpAlloc); }

bool alloc_should_fail(AllocKind kind) {
    if (!(g_faults.alloc_mask.load() & static_cast<unsigned>(kind))) return false;
    bool fail = op_should_fail(kOpAlloc);
    const char *name = "alloc";
    switch (kind) {
        case kAllocDictionary: name = "alloc.OSDictionary"; break;
        case kAllocArray: name = "alloc.OSArray"; break;
        case kAllocString: name = "alloc.OSString"; break;
        case kAllocSymbol: name = "alloc.OSSymbol"; break;
        case kAllocNumber: name = "alloc.OSNumber"; break;
        case kAllocLock: name = "alloc.IOLock"; break;
        case kAllocIterator: name = "alloc.OSCollectionIterator"; break;
        default: break;
    }
    trace_event(name, fail ? 1 : 0);
    return fail;
}

void fail_next_thread_start() { arm_op_failure(kOpThreadStart, 1, false); }
void fail_next_super_init() { g_faults.super_init = true; }
void fail_next_super_start() { g_faults.super_start = true; }
void fail_next_super_init_with_task() { g_faults.super_init_with_task = true; }
void fail_next_set_property() { g_faults.super_set_property = true; }

void seed_rng(uint64_t seed) { g_rng = seed; }

uint64_t next_random() {
    uint64_t x = g_rng.load(std::memory_order_relaxed);
    uint64_t y;
    do {
        y = x ? x : 0x9e3779b97f4a7c15ull;
        y ^= y << 13;
        y ^= y >> 7;
        y ^= y << 17;
    } while (!g_rng.compare_exchange_weak(x, y, std::memory_order_relaxed));
    return y;
}

static void maybe_yield() {
    if (g_rng.load(std::memory_order_relaxed) != 0 && (next_random() & 3u) == 0) sched_yield();
}

void violation(const char *fmt, ...) {
    ++g_stats.violations;
    va_list ap;
    va_start(ap, fmt);
    fputs("SHIM VIOLATION: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

void trace_event(const char *op, long result) {
    if (g_quiescent.load() && tls_is_worker) {
        ++g_stats.post_teardown_ops;
        violation("worker thread called %s after stop()/free() returned", op);
    }
    unsigned long s = g_trace_seq.fetch_add(1) + 1;
    TraceEntry &e = g_trace[s % kTraceSize];
    e.op.store(op, std::memory_order_relaxed);
    e.result.store(result, std::memory_order_relaxed);
    e.thread.store(current_thread_id() * 2 + (tls_is_worker ? 1 : 0), std::memory_order_relaxed);
    e.seq.store(s, std::memory_order_release);
}

void dump_trace(FILE *out, unsigned count) {
    unsigned long cur = g_trace_seq.load();
    if (count > kTraceSize) count = kTraceSize;
    unsigned long first = cur >= count ? cur - count + 1 : 1;
    fprintf(out, "  last shim calls (seq thread op -> result; 'w' = kext worker thread):\n");
    for (unsigned long s = first; s <= cur; ++s) {
        const TraceEntry &e = g_trace[s % kTraceSize];
        if (e.seq.load(std::memory_order_acquire) != s) continue;
        unsigned t = e.thread.load(std::memory_order_relaxed);
        fprintf(out, "    #%lu T%u%s %s -> %ld\n", s, t / 2, (t & 1) ? "w" : "", e.op.load(std::memory_order_relaxed),
                e.result.load(std::memory_order_relaxed));
    }
    fflush(out);
}

void mark_quiescent() {
    if (g_stats.workers_running.load() != 0)
        violation("worker still running when the object reported stopped/freed (%ld running)",
                  g_stats.workers_running.load());
    g_quiescent = true;
}

void clear_quiescent() { g_quiescent = false; }

static uintptr_t self_id() {
    static thread_local char tag;
    return reinterpret_cast<uintptr_t>(&tag);
}

}  // namespace kext_shim

using namespace kext_shim;

// ---------------------------------------------------------------------------
// OSObject
// ---------------------------------------------------------------------------

OSObject::OSObject() : refs_(1), free_chained_(false) { ++g_stats.live_objects; }

OSObject::~OSObject() { --g_stats.live_objects; }

void *OSObject::operator new(size_t size) {
    void *p = malloc(size);
    if (!p) abort();
    memset(p, 0, size);
    return p;
}

void OSObject::operator delete(void *p) { ::free(p); }

void OSObject::free() { free_chained_ = true; }

void OSObject::retain() const {
    int prev = refs_.fetch_add(1);
    if (prev <= 0) violation("retain of object with retain count %d", prev);
}

void OSObject::release() const {
    int prev = refs_.fetch_sub(1);
    if (prev <= 0) {
        refs_.fetch_add(1);
        violation("over-release (retain count was %d)", prev);
        return;
    }
    if (prev == 1) {
        OSObject *self = const_cast<OSObject *>(this);
        self->free();
        if (!self->free_chained_) violation("free() did not chain to OSObject::free()");
        delete self;
    }
}

static OSBoolean s_true(true);
static OSBoolean s_false(false);
OSBoolean *const kOSBooleanTrue = &s_true;
OSBoolean *const kOSBooleanFalse = &s_false;

// ---------------------------------------------------------------------------
// OSString / OSSymbol / OSNumber
// ---------------------------------------------------------------------------

OSString *OSString::withCString(const char *cString) {
    if (!cString || alloc_should_fail(kAllocString)) return NULL;
    OSString *s = new OSString;
    s->str_ = cString;
    return s;
}

const OSSymbol *OSSymbol::withCString(const char *cString) {
    if (!cString || alloc_should_fail(kAllocSymbol)) return NULL;
    OSSymbol *s = new OSSymbol;
    s->str_ = cString;
    return s;
}

OSNumber *OSNumber::withNumber(unsigned long long value, unsigned int numberOfBits) {
    if (alloc_should_fail(kAllocNumber)) return NULL;
    OSNumber *n = new OSNumber;
    n->value_ = value;
    n->bits_ = numberOfBits;
    return n;
}

// ---------------------------------------------------------------------------
// OSArray
// ---------------------------------------------------------------------------

OSArray *OSArray::withCapacity(unsigned int capacity) {
    (void)capacity;
    if (alloc_should_fail(kAllocArray)) return NULL;
    return new OSArray;
}

bool OSArray::setObject(const OSMetaClassBase *object) {
    return setObject(getCount(), object);
}

bool OSArray::setObject(unsigned int index, const OSMetaClassBase *object) {
    if (!object || index > objects_.size()) return false;
    OSObject *o = const_cast<OSObject *>(object);
    o->retain();
    objects_.insert(objects_.begin() + index, o);
    return true;
}

OSObject *OSArray::getObject(unsigned int index) const {
    return index < objects_.size() ? objects_[index] : NULL;
}

void OSArray::free() {
    for (size_t i = 0; i < objects_.size(); ++i) objects_[i]->release();
    objects_.clear();
    OSObject::free();
}

// ---------------------------------------------------------------------------
// OSDictionary
// ---------------------------------------------------------------------------

OSDictionary *OSDictionary::withCapacity(unsigned int capacity) {
    (void)capacity;
    if (alloc_should_fail(kAllocDictionary)) return NULL;
    return new OSDictionary;
}

OSDictionary *OSDictionary::withDictionary(const OSDictionary *dict, unsigned int capacity) {
    (void)capacity;
    if (!dict || alloc_should_fail(kAllocDictionary)) return NULL;
    OSDictionary *copy = new OSDictionary;
    for (size_t i = 0; i < dict->entries_.size(); ++i) {
        const Entry &e = dict->entries_[i];
        e.key->retain();
        e.value->retain();
        Entry c = {e.key, e.value};
        copy->entries_.push_back(c);
    }
    return copy;
}

OSObject *OSDictionary::iterationObjectAt(unsigned int index) const {
    return index < entries_.size() ? const_cast<OSSymbol *>(entries_[index].key) : NULL;
}

bool OSDictionary::store(const OSSymbol *key, const OSMetaClassBase *object) {
    if (!key || !object) return false;
    OSObject *o = const_cast<OSObject *>(object);
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].key->isEqualTo(key)) {
            o->retain();
            OSObject *old = entries_[i].value;
            entries_[i].value = o;
            old->release();
            return true;
        }
    }
    key->retain();
    o->retain();
    Entry e = {key, o};
    entries_.push_back(e);
    return true;
}

bool OSDictionary::setObject(const OSSymbol *key, const OSMetaClassBase *object) {
    return store(key, object);
}

bool OSDictionary::setObject(const char *key, const OSMetaClassBase *object) {
    if (!key || !object) return false;
    const OSSymbol *sym = OSSymbol::withCString(key);
    if (!sym) return false;
    bool ok = store(sym, object);
    sym->release();
    return ok;
}

bool OSDictionary::setObject(const OSString *key, const OSMetaClassBase *object) {
    return key && setObject(key->getCStringNoCopy(), object);
}

OSObject *OSDictionary::lookup(const char *key) const {
    if (!key) return NULL;
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].key->isEqualTo(key)) return entries_[i].value;
    }
    return NULL;
}

OSObject *OSDictionary::getObject(const OSSymbol *key) const {
    return key ? lookup(key->getCStringNoCopy()) : NULL;
}

OSObject *OSDictionary::getObject(const OSString *key) const {
    return key ? lookup(key->getCStringNoCopy()) : NULL;
}

OSObject *OSDictionary::getObject(const char *key) const { return lookup(key); }

void OSDictionary::free() {
    for (size_t i = 0; i < entries_.size(); ++i) {
        entries_[i].key->release();
        entries_[i].value->release();
    }
    entries_.clear();
    OSObject::free();
}

// ---------------------------------------------------------------------------
// OSCollectionIterator
// ---------------------------------------------------------------------------

OSCollectionIterator *OSCollectionIterator::withCollection(const OSCollection *collection) {
    if (!collection || alloc_should_fail(kAllocIterator)) return NULL;
    OSCollectionIterator *it = new OSCollectionIterator;
    collection->retain();
    it->collection_ = collection;
    it->index_ = 0;
    return it;
}

OSObject *OSCollectionIterator::getNextObject() {
    if (!collection_ || index_ >= collection_->getCount()) return NULL;
    return collection_->iterationObjectAt(index_++);
}

void OSCollectionIterator::free() {
    if (collection_) {
        collection_->release();
        collection_ = NULL;
    }
    OSObject::free();
}

// ---------------------------------------------------------------------------
// IOLock
// ---------------------------------------------------------------------------

namespace {
struct Waiter {
    void *event;
    bool signaled;
};
}  // namespace

struct IOLock {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    std::atomic<uintptr_t> owner;
    std::atomic<bool> freed;
    std::atomic<long> acquires;   // lock + wakeups from IOLockSleep
    std::atomic<long> releases;   // unlock + entries into IOLockSleep
    std::vector<Waiter *> waiters;  // guarded by mutex
};

namespace {
pthread_mutex_t g_lock_graveyard_mutex = PTHREAD_MUTEX_INITIALIZER;
// Freed locks are kept (flagged, mutex destroyed) so a use after IOLockFree is reported deterministically
// by the shim instead of depending on allocator behavior.
std::vector<IOLock *> &lock_graveyard() {
    static std::vector<IOLock *> *graveyard = new std::vector<IOLock *>;
    return *graveyard;
}

bool lock_usable(IOLock *lock, const char *what) {
    if (lock->freed.load()) {
        violation("%s on a freed lock", what);
        return false;
    }
    return true;
}
}  // namespace

IOLock *IOLockAlloc(void) {
    bool failed_alloc = alloc_should_fail(kAllocLock);
    bool failed_lock = op_should_fail(kOpLockAlloc);
    trace_event("IOLockAlloc", (failed_alloc || failed_lock) ? 1 : 0);
    if (failed_alloc || failed_lock) return NULL;
    IOLock *lock = new IOLock;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&lock->mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    pthread_cond_init(&lock->cond, NULL);
    lock->owner.store(0);
    lock->freed.store(false);
    lock->acquires.store(0);
    lock->releases.store(0);
    ++g_stats.live_locks;
    return lock;
}

void IOLockFree(IOLock *lock) {
    trace_event("IOLockFree", 0);
    if (!lock) {
        violation("IOLockFree(NULL)");
        return;
    }
    if (lock->freed.exchange(true)) {
        violation("IOLockFree on an already freed lock");
        return;
    }
    if (lock->owner.load() != 0) violation("IOLockFree on a held lock");
    if (!lock->waiters.empty()) violation("IOLockFree with sleeping waiters");
    if (lock->acquires.load() != lock->releases.load())
        violation("IOLockFree with unbalanced lock/unlock (%ld acquires, %ld releases)", lock->acquires.load(),
                  lock->releases.load());
    pthread_cond_destroy(&lock->cond);
    pthread_mutex_destroy(&lock->mutex);
    std::vector<Waiter *>().swap(lock->waiters);
    --g_stats.live_locks;
    pthread_mutex_lock(&g_lock_graveyard_mutex);
    lock_graveyard().push_back(lock);
    pthread_mutex_unlock(&g_lock_graveyard_mutex);
}

void IOLockLock(IOLock *lock) {
    trace_event("IOLockLock", 0);
    if (!lock_usable(lock, "IOLockLock")) return;
    maybe_yield();
    int rc = pthread_mutex_lock(&lock->mutex);
    if (rc != 0) {
        violation("IOLockLock failed (%d): recursive lock or invalid lock", rc);
        return;
    }
    lock->owner.store(self_id());
    ++lock->acquires;
    ++g_stats.locks_held;
}

void IOLockUnlock(IOLock *lock) {
    trace_event("IOLockUnlock", 0);
    if (!lock_usable(lock, "IOLockUnlock")) return;
    if (lock->owner.load() != self_id()) {
        violation("IOLockUnlock by a thread that does not hold the lock");
        return;
    }
    lock->owner.store(0);
    ++lock->releases;
    --g_stats.locks_held;
    pthread_mutex_unlock(&lock->mutex);
    maybe_yield();
}

int IOLockSleep(IOLock *lock, void *event, UInt32 interType) {
    (void)interType;
    trace_event("IOLockSleep", 0);
    if (!lock_usable(lock, "IOLockSleep")) return THREAD_AWAKENED;
    if (lock->owner.load() != self_id()) {
        violation("IOLockSleep without holding the lock");
        return THREAD_AWAKENED;
    }
    Waiter w = {event, false};
    lock->waiters.push_back(&w);
    lock->owner.store(0);
    ++lock->releases;
    --g_stats.locks_held;
    while (!w.signaled) pthread_cond_wait(&lock->cond, &lock->mutex);
    lock->owner.store(self_id());
    ++lock->acquires;
    ++g_stats.locks_held;
    return THREAD_AWAKENED;
}

void IOLockWakeup(IOLock *lock, void *event, bool oneThread) {
    trace_event("IOLockWakeup", oneThread ? 1 : 0);
    if (!lock_usable(lock, "IOLockWakeup")) return;
    bool owned = lock->owner.load() == self_id();
    if (!owned) pthread_mutex_lock(&lock->mutex);
    for (size_t i = 0; i < lock->waiters.size();) {
        if (lock->waiters[i]->event == event) {
            lock->waiters[i]->signaled = true;
            lock->waiters.erase(lock->waiters.begin() + i);
            if (oneThread) break;
        } else {
            ++i;
        }
    }
    pthread_cond_broadcast(&lock->cond);
    if (!owned) pthread_mutex_unlock(&lock->mutex);
}

// ---------------------------------------------------------------------------
// Threads / logging
// ---------------------------------------------------------------------------

struct thread {
    pthread_t handle;
    std::atomic<int> dealloc_calls;
    thread_continue_t fn;
    void *arg;
};

namespace {
pthread_mutex_t g_thread_registry_lock = PTHREAD_MUTEX_INITIALIZER;
std::vector<thread *> &thread_registry() {
    static std::vector<thread *> *registry = new std::vector<thread *>;
    return *registry;
}

void *thread_trampoline(void *p) {
    thread *t = static_cast<thread *>(p);
    set_worker_thread(true);
    ++g_stats.workers_running;
    trace_event("worker_start", 0);
    t->fn(t->arg, 0);
    trace_event("worker_end", 0);
    --g_stats.workers_running;
    return NULL;
}
}  // namespace

kern_return_t kernel_thread_start(thread_continue_t continuation, void *parameter, thread_t *newThread) {
    bool injected = op_should_fail(kOpThreadStart);
    trace_event("kernel_thread_start", injected ? KERN_FAILURE : KERN_SUCCESS);
    if (injected) return KERN_FAILURE;
    thread *t = new thread;
    t->dealloc_calls = 0;
    t->fn = continuation;
    t->arg = parameter;
    if (pthread_create(&t->handle, NULL, thread_trampoline, t) != 0) {
        delete t;
        return KERN_FAILURE;
    }
    pthread_mutex_lock(&g_thread_registry_lock);
    thread_registry().push_back(t);  // never freed: a second thread_deallocate must stay detectable
    pthread_mutex_unlock(&g_thread_registry_lock);
    ++g_stats.threads_started;
    *newThread = t;
    return KERN_SUCCESS;
}

void thread_deallocate(thread_t t) {
    trace_event("thread_deallocate", 0);
    if (t == THREAD_NULL) {
        violation("thread_deallocate(THREAD_NULL)");
        return;
    }
    if (t->dealloc_calls.fetch_add(1) != 0) {
        violation("thread_deallocate called more than once for one thread");
        return;
    }
    // Reaping includes waiting for the body to return, so no code runs after the owner frees itself.
    pthread_join(t->handle, NULL);
    ++g_stats.thread_deallocs;
}

void IOSleepWithLeeway(unsigned int intervalMilliseconds, unsigned int leewayMilliseconds) {
    (void)leewayMilliseconds;
    unsigned ms = std::min(intervalMilliseconds, g_sleep_cap_ms.load());
    if (ms > 0 && g_rng.load(std::memory_order_relaxed) != 0) ms = static_cast<unsigned>(next_random() % (ms + 1u));
    trace_event("IOSleepWithLeeway", ms);
    if (ms == 0) {
        sched_yield();
    } else {
        usleep(ms * 1000u);
    }
}

static bool verbose_logging() {
    static const bool verbose = getenv("KEXT_HARNESS_VERBOSE") != NULL;
    return verbose;
}

void IOLog(const char *format, ...) {
    if (!verbose_logging()) return;
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

void kprintf(const char *format, ...) { (void)format; }

// ---------------------------------------------------------------------------
// IOService / IOUserClient
// ---------------------------------------------------------------------------

IOService::IOService() : shim_start_calls(0), shim_stop_calls(0), shim_register_calls(0), properties_(NULL) {}

IOService::~IOService() {}

bool IOService::init(OSDictionary *dictionary) {
    if (consume(g_faults.super_init)) {
        trace_event("IOService::init", 0);
        return false;
    }
    if (properties_) {
        properties_->release();
        properties_ = NULL;
    }
    properties_ = dictionary ? OSDictionary::withDictionary(dictionary) : OSDictionary::withCapacity(2);
    trace_event("IOService::init", properties_ != NULL);
    return properties_ != NULL;
}

void IOService::free() {
    if (properties_) {
        properties_->release();
        properties_ = NULL;
    }
    OSObject::free();
}

bool IOService::start(IOService *provider) {
    (void)provider;
    ++shim_start_calls;
    bool ok = !consume(g_faults.super_start);
    trace_event("IOService::start", ok);
    return ok;
}

void IOService::stop(IOService *provider) {
    (void)provider;
    trace_event("IOService::stop", 0);
    ++shim_stop_calls;
}

// Models the call a driver makes into its provider: the harness can fail it with kOpSetProperties.
IOReturn IOService::setProperties(OSObject *properties) {
    (void)properties;
    bool injected = op_should_fail(kOpSetProperties);
    trace_event("IOService::setProperties", injected ? 1 : 0);
    return injected ? kIOReturnNoMemory : kIOReturnSuccess;
}

void IOService::registerService(IOOptionBits options) {
    (void)options;
    trace_event("IOService::registerService", 0);
    ++shim_register_calls;
}

bool IOService::setProperty(const OSSymbol *key, OSObject *value) {
    if (consume(g_faults.super_set_property)) {
        trace_event("IOService::setProperty", 0);
        return false;
    }
    bool ok = properties_ && properties_->setObject(key, value);
    trace_event("IOService::setProperty", ok);
    return ok;
}

bool IOService::setProperty(const char *key, OSObject *value) {
    if (consume(g_faults.super_set_property)) {
        trace_event("IOService::setProperty", 0);
        return false;
    }
    bool ok = properties_ && properties_->setObject(key, value);
    trace_event("IOService::setProperty", ok);
    return ok;
}

OSObject *IOService::getProperty(const OSSymbol *key) const {
    return properties_ ? properties_->getObject(key) : NULL;
}

OSObject *IOService::getProperty(const char *key) const {
    return properties_ ? properties_->getObject(key) : NULL;
}

bool IOUserClient::initWithTask(task_t owningTask, void *securityToken, UInt32 type, OSDictionary *properties) {
    (void)owningTask;
    (void)securityToken;
    (void)type;
    bool failed = consume(g_faults.super_init_with_task);
    trace_event("IOUserClient::initWithTask", failed ? 0 : 1);
    if (failed) return false;
    return IOService::init(properties);
}

IOReturn IOUserClient::clientClose(void) { return kIOReturnUnsupported; }

IOReturn IOUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                                      IOExternalMethodDispatch *dispatch, OSObject *target, void *reference) {
    (void)selector;
    trace_event("IOUserClient::externalMethod", selector);
    if (!dispatch || !dispatch->function) return kIOReturnUnsupported;
    if (!target) target = this;
    if (arguments) {
        if (dispatch->checkScalarInputCount != 0xffffffffu && arguments->scalarInputCount != dispatch->checkScalarInputCount)
            return kIOReturnBadArgument;
        if (dispatch->checkStructureInputSize != 0xffffffffu &&
            arguments->structureInputSize != dispatch->checkStructureInputSize)
            return kIOReturnBadArgument;
        if (dispatch->checkScalarOutputCount != 0xffffffffu &&
            arguments->scalarOutputCount != dispatch->checkScalarOutputCount)
            return kIOReturnBadArgument;
        if (dispatch->checkStructureOutputSize != 0xffffffffu &&
            arguments->structureOutputSize != dispatch->checkStructureOutputSize)
            return kIOReturnBadArgument;
    }
    return (*dispatch->function)(target, reference, arguments);
}
