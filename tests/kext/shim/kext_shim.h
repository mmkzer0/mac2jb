// User-space replacement for the slice of IOKit / libkern / XNU the usbgadget kext uses.
// All IOKit shim headers include this file. Compile with RTTI (OSDynamicCast is dynamic_cast).
#ifndef KEXT_SHIM_H
#define KEXT_SHIM_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atomic>
#include <string>
#include <type_traits>
#include <vector>

class OSSymbol;
class IOService;

typedef uint32_t UInt32;
typedef uint32_t IOOptionBits;
typedef int kern_return_t;
typedef int IOReturn;
typedef int wait_result_t;
typedef unsigned int wait_interrupt_t;
typedef struct task *task_t;
typedef struct thread *thread_t;
typedef void (*thread_continue_t)(void *, wait_result_t);

#define KERN_SUCCESS 0
#define KERN_FAILURE 5
#define THREAD_NULL ((thread_t)0)
#define THREAD_UNINT 0
#define THREAD_AWAKENED 0

static const IOReturn kIOReturnSuccess = 0;
static const IOReturn kIOReturnNoMemory = static_cast<IOReturn>(0xe00002bdu);
static const IOReturn kIOReturnUnsupported = static_cast<IOReturn>(0xe00002c7u);
static const IOReturn kIOReturnBadArgument = static_cast<IOReturn>(0xe00002c2u);
static const IOReturn kIOReturnNotReady = static_cast<IOReturn>(0xe00002d8u);

#define OSDynamicCast(type, inst) (::kext_shim::dynamic_cast_helper<type>(inst))

namespace kext_shim {

template <class T, class U>
inline T *dynamic_cast_helper(U *p) {
    return dynamic_cast<T *>(const_cast<typename std::remove_const<U>::type *>(p));
}

// ---------------------------------------------------------------------------
// Control / fault injection / accounting
// ---------------------------------------------------------------------------

enum AllocKind {
    kAllocDictionary = 1u << 0,
    kAllocArray = 1u << 1,
    kAllocString = 1u << 2,
    kAllocSymbol = 1u << 3,
    kAllocNumber = 1u << 4,
    kAllocLock = 1u << 5,
    kAllocIterator = 1u << 6,
    kAllocAllKinds = 0x7fu
};

struct Stats {
    std::atomic<long> live_objects;        // OSObject instances alive (includes the two immortal OSBooleans)
    std::atomic<long> live_locks;          // IOLock instances alive
    std::atomic<long> locks_held;          // locks currently held by some thread (sleep counts as released)
    std::atomic<long> threads_started;     // successful kernel_thread_start calls
    std::atomic<long> thread_deallocs;     // first thread_deallocate per thread
    std::atomic<long> workers_running;     // thread bodies currently executing
    std::atomic<long> violations;          // shim-detected contract violations
    std::atomic<long> post_teardown_ops;   // worker-thread shim calls after mark_quiescent()
};

struct Faults {
    std::atomic<unsigned> alloc_mask;  // AllocKind bits that count toward / can be failed by kOpAlloc
    std::atomic<bool> super_init;
    std::atomic<bool> super_start;
    std::atomic<bool> super_init_with_task;
    std::atomic<bool> super_set_property;
};

// Shim-mediated operations that failure sweeps can target. Each has its own 1-based sequence.
enum Op {
    kOpAlloc = 0,         // every tracked allocation (OSDictionary/OSArray/OSString/OSSymbol/OSNumber/iterator/IOLock)
    kOpLockAlloc,         // IOLockAlloc only (also counted under kOpAlloc)
    kOpThreadStart,       // kernel_thread_start
    kOpSetProperties,     // IOService::setProperties (the base implementation, i.e. calls into the provider)
    kOpCount
};

extern Stats g_stats;
extern Faults g_faults;
extern std::atomic<unsigned> g_sleep_cap_ms;

// Clears all fault state and per-run counters. live_objects and locks_held are intentionally preserved.
void reset();

// Generic failure injection: fail the nth `op` after this call (one-shot), or the nth and every later one (sticky).
void arm_op_failure(Op op, unsigned long nth, bool sticky);
void disarm_op_failures();
bool op_failure_fired(Op op);
unsigned long op_count(Op op);          // operations of this kind seen since arm/reset
int op_failure_step(Op op);             // set_step() value when the injection first fired, -1 if not fired
bool op_should_fail(Op op);             // counts one operation; true when it must fail
const char *op_name(Op op);
// Harness-provided phase marker, recorded when an injection fires.
void set_step(int step);

// Convenience wrappers over the generic API for kOpAlloc / kOpThreadStart.
// Fails the nth tracked allocation of a kind in `kind_mask` after this call (one-shot unless sticky).
void arm_alloc_failure(unsigned long nth, unsigned kind_mask = kAllocAllKinds, bool sticky = false);
void disarm_alloc_failure();
bool alloc_failure_fired();
bool alloc_should_fail(AllocKind kind);
void fail_next_thread_start();
void fail_next_super_init();
void fail_next_super_start();
void fail_next_super_init_with_task();
void fail_next_set_property();
// Test-only observation point after IOService::setProperty applies the value and
// before it returns. Used to force a deterministic two-writer publication race.
using SetPropertyObserver = void (*)(const OSSymbol *key, bool applied, void *context);
void set_set_property_observer(SetPropertyObserver observer, void *context);

// Seeded scheduling/timing RNG: jitters IOSleepWithLeeway and inserts yields around lock operations.
// Seed 0 (the initial state) disables jitter.
void seed_rng(uint64_t seed);
uint64_t next_random();

// Fixed ring buffer of shim-mediated calls: {seq, op, result, thread}.
void trace_event(const char *op, long result);
void dump_trace(FILE *out, unsigned count);

// After the object under test has been stopped/freed, no kext-created worker thread may call into the shim.
// mark_quiescent() also verifies that every started worker was released with thread_deallocate.
void mark_quiescent();
void clear_quiescent();

// thread_deallocate only drops the owner's reference, as in XNU: it never waits for the worker. This joins
// every worker its owner has released, so a test can assert that no worker is still running.
void reap_released_threads();

// IOKit's termination thread for a service whose terminate() was requested: stop(provider), then
// detach(provider). No-op for an active or unattached service.
void complete_termination(IOService *service);

// Prints a shim violation to stderr and counts it.
void violation(const char *fmt, ...);

}  // namespace kext_shim

// ---------------------------------------------------------------------------
// OSObject and containers
// ---------------------------------------------------------------------------

#define OSDeclareDefaultStructors(className) \
  public:                                    \
    className();                             \
    virtual ~className();                    \
  private:

#define OSDefineMetaClassAndStructors(className, superName) \
    className::className() {}                               \
    className::~className() {}

class OSObject {
  public:
    OSObject();
    virtual ~OSObject();

    virtual void free();
    virtual void retain() const;
    virtual void release() const;
    int getRetainCount() const { return refs_.load(); }

    // Kernel OSObject storage is zero-filled before the constructor runs.
    static void *operator new(size_t size);
    static void operator delete(void *p);

  private:
    OSObject(const OSObject &) = delete;
    OSObject &operator=(const OSObject &) = delete;

    mutable std::atomic<int> refs_;
    bool free_chained_;
};

typedef OSObject OSMetaClassBase;

class OSBoolean : public OSObject {
  public:
    explicit OSBoolean(bool v) : value_(v) {}
    bool getValue() const { return value_; }
    virtual void retain() const override {}
    virtual void release() const override {}

  private:
    bool value_;
};

extern OSBoolean *const kOSBooleanTrue;
extern OSBoolean *const kOSBooleanFalse;

class OSString : public OSObject {
  public:
    static OSString *withCString(const char *cString);
    const char *getCStringNoCopy() const { return str_.c_str(); }
    bool isEqualTo(const char *other) const { return other && str_ == other; }
    bool isEqualTo(const OSString *other) const { return other && str_ == other->str_; }

  protected:
    std::string str_;
};

class OSSymbol : public OSString {
  public:
    static const OSSymbol *withCString(const char *cString);
    using OSString::isEqualTo;
    bool isEqualTo(const OSSymbol *other) const { return other && str_ == other->str_; }
};

class OSNumber : public OSObject {
  public:
    static OSNumber *withNumber(unsigned long long value, unsigned int numberOfBits);
    unsigned long long unsigned64BitValue() const { return value_; }
    unsigned int numberOfBits() const { return bits_; }

  private:
    unsigned long long value_;
    unsigned int bits_;
};

class OSCollection : public OSObject {
  public:
    virtual unsigned int getCount() const = 0;
    // Shim-internal: element i as seen by OSCollectionIterator (dictionary key / array object).
    virtual OSObject *iterationObjectAt(unsigned int index) const = 0;
};

class OSArray : public OSCollection {
  public:
    static OSArray *withCapacity(unsigned int capacity);
    virtual unsigned int getCount() const override { return static_cast<unsigned int>(objects_.size()); }
    virtual OSObject *iterationObjectAt(unsigned int index) const override { return getObject(index); }
    bool setObject(const OSMetaClassBase *object);
    bool setObject(unsigned int index, const OSMetaClassBase *object);
    OSObject *getObject(unsigned int index) const;
    virtual void free() override;

  private:
    std::vector<OSObject *> objects_;
};

class OSDictionary : public OSCollection {
  public:
    static OSDictionary *withCapacity(unsigned int capacity);
    static OSDictionary *withDictionary(const OSDictionary *dict, unsigned int capacity = 0);
    virtual unsigned int getCount() const override { return static_cast<unsigned int>(entries_.size()); }
    virtual OSObject *iterationObjectAt(unsigned int index) const override;
    bool setObject(const OSSymbol *key, const OSMetaClassBase *object);
    bool setObject(const OSString *key, const OSMetaClassBase *object);
    bool setObject(const char *key, const OSMetaClassBase *object);
    OSObject *getObject(const OSSymbol *key) const;
    OSObject *getObject(const OSString *key) const;
    OSObject *getObject(const char *key) const;
    virtual void free() override;

  private:
    struct Entry {
        const OSSymbol *key;
        OSObject *value;
    };
    OSObject *lookup(const char *key) const;
    bool store(const OSSymbol *key, const OSMetaClassBase *object);
    std::vector<Entry> entries_;
};

class OSCollectionIterator : public OSObject {
  public:
    static OSCollectionIterator *withCollection(const OSCollection *collection);
    OSObject *getNextObject();
    void reset() { index_ = 0; }
    virtual void free() override;

  private:
    const OSCollection *collection_;
    unsigned int index_;
};

// ---------------------------------------------------------------------------
// IOLock / threads / logging
// ---------------------------------------------------------------------------

struct IOLock;
typedef struct IOLock IOLock;

IOLock *IOLockAlloc(void);
void IOLockFree(IOLock *lock);
void IOLockLock(IOLock *lock);
void IOLockUnlock(IOLock *lock);
// Atomically releases `lock`, sleeps until IOLockWakeup(event), and retakes `lock`.
int IOLockSleep(IOLock *lock, void *event, UInt32 interType);
void IOLockWakeup(IOLock *lock, void *event, bool oneThread);

kern_return_t kernel_thread_start(thread_continue_t continuation, void *parameter, thread_t *newThread);
void thread_deallocate(thread_t thread);
void IOSleepWithLeeway(unsigned int intervalMilliseconds, unsigned int leewayMilliseconds);
void IOLog(const char *format, ...);
void kprintf(const char *format, ...);

// ---------------------------------------------------------------------------
// IOService / IOUserClient
// ---------------------------------------------------------------------------

class IOService : public OSObject {
  public:
    IOService();
    virtual ~IOService();

    virtual bool init(OSDictionary *dictionary = 0);
    virtual void free() override;
    virtual bool start(IOService *provider);
    virtual void stop(IOService *provider);
    virtual IOReturn setProperties(OSObject *properties);
    virtual void registerService(IOOptionBits options = 0);

    // Registry attachment holds a reference on both entries until detach().
    virtual bool attach(IOService *provider);
    virtual void detach(IOService *provider);
    // Marks the service inactive and returns true only for the first call. As in IOKit, stop() and
    // detach() run later on the termination thread; kext_shim::complete_termination() models that step.
    virtual bool terminate(IOOptionBits options = 0);
    bool isInactive() const { return shim_inactive_.load(); }

    virtual bool setProperty(const OSSymbol *key, OSObject *value);
    bool setProperty(const char *key, OSObject *value);
    OSObject *getProperty(const OSSymbol *key) const;
    OSObject *getProperty(const char *key) const;

    // Shim observation counters.
    std::atomic<int> shim_start_calls;
    std::atomic<int> shim_stop_calls;
    std::atomic<int> shim_register_calls;
    std::atomic<int> shim_terminate_calls;

  private:
    friend void kext_shim::complete_termination(IOService *service);

    OSDictionary *properties_;
    std::atomic<bool> shim_inactive_;
    IOService *shim_provider_;  // set by attach(), cleared by detach()
};

struct IOExternalMethodArguments {
    uint32_t version;
    uint32_t selector;
    const uint64_t *scalarInput;
    uint32_t scalarInputCount;
    const void *structureInput;
    uint32_t structureInputSize;
    uint64_t *scalarOutput;
    uint32_t scalarOutputCount;
    void *structureOutput;
    uint32_t structureOutputSize;
};

typedef IOReturn (*IOExternalMethodAction)(OSObject *target, void *reference, IOExternalMethodArguments *arguments);

struct IOExternalMethodDispatch {
    IOExternalMethodAction function;
    uint32_t checkScalarInputCount;
    uint32_t checkStructureInputSize;
    uint32_t checkScalarOutputCount;
    uint32_t checkStructureOutputSize;
};

class IOUserClient : public IOService {
  public:
    virtual bool initWithTask(task_t owningTask, void *securityToken, UInt32 type, OSDictionary *properties);
    virtual IOReturn clientClose(void);
    virtual IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                                    IOExternalMethodDispatch *dispatch = 0, OSObject *target = 0,
                                    void *reference = 0);
};

#endif  // KEXT_SHIM_H
