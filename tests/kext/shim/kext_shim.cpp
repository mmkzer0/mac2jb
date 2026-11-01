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

static bool consume(std::atomic<bool> &flag) { return flag.exchange(false); }

void reset() {
    g_stats.threads_started = 0;
    g_stats.thread_deallocs = 0;
    g_stats.workers_running = 0;
    g_stats.violations = 0;
    g_stats.alloc_seen = 0;
    g_faults.alloc_fail_at = 0;
    g_faults.alloc_mask = kAllocAllKinds;
    g_faults.alloc_sticky = false;
    g_faults.alloc_fired = false;
    g_faults.thread_start = false;
    g_faults.super_init = false;
    g_faults.super_start = false;
    g_faults.super_init_with_task = false;
    g_sleep_cap_ms = 2;
}

void arm_alloc_failure(unsigned long nth, unsigned kind_mask, bool sticky) {
    g_stats.alloc_seen = 0;
    g_faults.alloc_fired = false;
    g_faults.alloc_mask = kind_mask;
    g_faults.alloc_sticky = sticky;
    g_faults.alloc_fail_at = nth;
}

void disarm_alloc_failure() { g_faults.alloc_fail_at = 0; }

bool alloc_failure_fired() { return g_faults.alloc_fired.load(); }

bool alloc_should_fail(AllocKind kind) {
    if (!(g_faults.alloc_mask.load() & static_cast<unsigned>(kind))) return false;
    long n = ++g_stats.alloc_seen;
    unsigned long at = g_faults.alloc_fail_at.load();
    if (at == 0) return false;
    if (static_cast<unsigned long>(n) == at || (g_faults.alloc_sticky.load() && static_cast<unsigned long>(n) > at)) {
        g_faults.alloc_fired = true;
        return true;
    }
    return false;
}

void fail_next_thread_start() { g_faults.thread_start = true; }
void fail_next_super_init() { g_faults.super_init = true; }
void fail_next_super_start() { g_faults.super_start = true; }
void fail_next_super_init_with_task() { g_faults.super_init_with_task = true; }

void violation(const char *fmt, ...) {
    ++g_stats.violations;
    va_list ap;
    va_start(ap, fmt);
    fputs("SHIM VIOLATION: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

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
    std::vector<Waiter *> waiters;  // guarded by mutex
};

IOLock *IOLockAlloc(void) {
    if (alloc_should_fail(kAllocLock)) return NULL;
    IOLock *lock = new IOLock;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&lock->mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    pthread_cond_init(&lock->cond, NULL);
    lock->owner.store(0);
    ++g_stats.live_locks;
    return lock;
}

void IOLockFree(IOLock *lock) {
    if (!lock) {
        violation("IOLockFree(NULL)");
        return;
    }
    if (lock->owner.load() != 0) violation("IOLockFree on a held lock");
    if (!lock->waiters.empty()) violation("IOLockFree with sleeping waiters");
    pthread_cond_destroy(&lock->cond);
    pthread_mutex_destroy(&lock->mutex);
    --g_stats.live_locks;
    delete lock;
}

void IOLockLock(IOLock *lock) {
    int rc = pthread_mutex_lock(&lock->mutex);
    if (rc != 0) {
        violation("IOLockLock failed (%d): recursive lock or invalid lock", rc);
        return;
    }
    lock->owner.store(self_id());
}

void IOLockUnlock(IOLock *lock) {
    if (lock->owner.load() != self_id()) {
        violation("IOLockUnlock by a thread that does not hold the lock");
        return;
    }
    lock->owner.store(0);
    pthread_mutex_unlock(&lock->mutex);
}

int IOLockSleep(IOLock *lock, void *event, UInt32 interType) {
    (void)interType;
    if (lock->owner.load() != self_id()) {
        violation("IOLockSleep without holding the lock");
        return THREAD_AWAKENED;
    }
    Waiter w = {event, false};
    lock->waiters.push_back(&w);
    lock->owner.store(0);
    while (!w.signaled) pthread_cond_wait(&lock->cond, &lock->mutex);
    lock->owner.store(self_id());
    return THREAD_AWAKENED;
}

void IOLockWakeup(IOLock *lock, void *event, bool oneThread) {
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
    ++g_stats.workers_running;
    t->fn(t->arg, 0);
    --g_stats.workers_running;
    return NULL;
}
}  // namespace

kern_return_t kernel_thread_start(thread_continue_t continuation, void *parameter, thread_t *newThread) {
    if (consume(g_faults.thread_start)) return KERN_FAILURE;
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
    if (consume(g_faults.super_init)) return false;
    if (properties_) {
        properties_->release();
        properties_ = NULL;
    }
    properties_ = dictionary ? OSDictionary::withDictionary(dictionary) : OSDictionary::withCapacity(2);
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
    return !consume(g_faults.super_start);
}

void IOService::stop(IOService *provider) {
    (void)provider;
    ++shim_stop_calls;
}

IOReturn IOService::setProperties(OSObject *properties) {
    (void)properties;
    return kIOReturnUnsupported;
}

void IOService::registerService(IOOptionBits options) {
    (void)options;
    ++shim_register_calls;
}

bool IOService::setProperty(const OSSymbol *key, OSObject *value) {
    return properties_ && properties_->setObject(key, value);
}

bool IOService::setProperty(const char *key, OSObject *value) {
    return properties_ && properties_->setObject(key, value);
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
    if (consume(g_faults.super_init_with_task)) return false;
    return IOService::init(properties);
}

IOReturn IOUserClient::clientClose(void) { return kIOReturnUnsupported; }

IOReturn IOUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                                      IOExternalMethodDispatch *dispatch, OSObject *target, void *reference) {
    (void)selector;
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
