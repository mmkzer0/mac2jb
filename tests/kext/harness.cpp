// Deterministic lifecycle / fault-injection harness for the usbgadget kext sources.
// The real kext translation units are compiled against tests/kext/shim (a user-space IOKit replacement).
// Every test runs in a forked child under a hard watchdog, so a hang fails that test instead of the binary.
//
// Build/run through scripts/test-kext-harness.sh.

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>

// The harness inspects and drives private lifecycle state (m_thread, m_provider, stopThread, ...)
// that the kext deliberately keeps private.
#define private public
#define protected public
#include "usbgadget.h"
#include "usbgadget_userclient.h"
#undef private
#undef protected

using namespace kext_shim;

namespace {

// ---------------------------------------------------------------------------
// Check helpers
// ---------------------------------------------------------------------------

std::atomic<int> g_failed_checks(0);

void check_failed(int line, const char *what) {
    ++g_failed_checks;
    fprintf(stderr, "  CHECK FAILED (harness.cpp:%d): %s\n", line, what);
    fflush(stderr);
}

void check_failedf(int line, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    check_failed(line, buf);
}

#define CHECK(cond)                                  \
    do {                                             \
        if (!(cond)) check_failed(__LINE__, #cond);  \
    } while (0)

#define CHECKF(cond, ...)                                 \
    do {                                                  \
        if (!(cond)) check_failedf(__LINE__, __VA_ARGS__); \
    } while (0)

void sleep_ms(unsigned ms) { usleep(ms * 1000u); }

bool wait_until(const std::function<bool()> &pred, unsigned timeout_ms) {
    std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        usleep(500);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Stand-in for the USB device controller provider. Optionally blocks inside setProperties() to model a
// slow controller while the gadget worker holds m_pokeLock.
class FakeController : public IOService {
  public:
    FakeController() : calls(0), block(false), entered(false), gate_open(true), last_param_count(0) {}

    virtual IOReturn setProperties(OSObject *props) override {
        OSDictionary *d = OSDynamicCast(OSDictionary, props);
        if (d) {
            std::lock_guard<std::mutex> guard(mu);
            OSString *cmd = OSDynamicCast(OSString, d->getObject("USBDeviceCommand"));
            last_command = cmd ? cmd->getCStringNoCopy() : "";
            OSDictionary *param = OSDynamicCast(OSDictionary, d->getObject("USBDeviceCommandParameter"));
            last_param_count = param ? param->getCount() : 0;
            OSString *serial = param ? OSDynamicCast(OSString, param->getObject("serialNumber")) : NULL;
            last_serial = serial ? serial->getCStringNoCopy() : "";
        }
        ++calls;
        if (block.load()) {
            entered = true;
            wait_until([this] { return gate_open.load(); }, 3000);
        }
        if (on_set_properties) on_set_properties();
        return IOService::setProperties(props);
    }

    std::string command() {
        std::lock_guard<std::mutex> guard(mu);
        return last_command;
    }
    std::string serial() {
        std::lock_guard<std::mutex> guard(mu);
        return last_serial;
    }
    unsigned param_count() {
        std::lock_guard<std::mutex> guard(mu);
        return last_param_count;
    }

    std::atomic<int> calls;
    std::atomic<bool> block;
    std::atomic<bool> entered;
    std::atomic<bool> gate_open;
    std::function<void()> on_set_properties;

  private:
    std::mutex mu;
    std::string last_command;
    std::string last_serial;
    unsigned last_param_count;
};

gay_bowser_usbgadget *new_gadget() {
    gay_bowser_usbgadget *g = new gay_bowser_usbgadget;
    bool ok = g->init(NULL);
    CHECK(ok);
    return g;
}

gay_bowser_usbgadget_userclient *new_userclient() {
    gay_bowser_usbgadget_userclient *uc = new gay_bowser_usbgadget_userclient;
    bool ok = uc->initWithTask(reinterpret_cast<task_t>(static_cast<uintptr_t>(1)), NULL, 0, NULL);
    CHECK(ok);
    return uc;
}

OSDictionary *make_config(const char *serial) {
    OSDictionary *d = OSDictionary::withCapacity(2);
    OSString *s = OSString::withCString(serial);
    OSNumber *n = OSNumber::withNumber(0x1234, 32);
    if (d && s && n) {
        d->setObject("serialNumber", s);
        d->setObject("productID", n);
    }
    if (s) s->release();
    if (n) n->release();
    return d;
}

OSDictionary *make_props(const char *key, OSObject *value) {
    OSDictionary *d = OSDictionary::withCapacity(1);
    if (d) d->setObject(key, value);
    return d;
}

// The unprivileged host sends CFSTR("Poke") as the value, not a boolean.
OSDictionary *make_poke_props() {
    OSString *value = OSString::withCString("Poke");
    OSDictionary *props = make_props("Poke", value);
    if (value) value->release();
    return props;
}

IOReturn poke(gay_bowser_usbgadget_userclient *uc) {
    IOExternalMethodArguments args;
    memset(&args, 0, sizeof(args));
    args.selector = gay_bowser_usbgadget_method_poke;
    return uc->externalMethod(gay_bowser_usbgadget_method_poke, &args, NULL, NULL, NULL);
}

void spin_until(const std::atomic<bool> &flag) {
    while (!flag.load()) std::this_thread::yield();
}

// ---------------------------------------------------------------------------
// Test 0: the shim's lock primitives behave like the kernel's (the other tests rely on them)
// ---------------------------------------------------------------------------

void test_shim_lock_semantics() {
    IOLock *l = IOLockAlloc();
    CHECK(l != NULL);
    int event = 0, other_event = 0;
    std::atomic<int> sleeping(0), woke(0);
    std::vector<std::thread> waiters;
    for (int i = 0; i < 3; ++i) {
        waiters.push_back(std::thread([&] {
            IOLockLock(l);
            ++sleeping;
            IOLockSleep(l, &event, THREAD_UNINT);
            ++woke;
            IOLockUnlock(l);
        }));
    }
    // Holding the lock with sleeping==3 proves every waiter released it atomically inside IOLockSleep.
    bool all_asleep = wait_until(
        [&] {
            IOLockLock(l);
            bool all = sleeping.load() == 3;
            IOLockUnlock(l);
            return all;
        },
        3000);
    CHECK(all_asleep);

    IOLockLock(l);
    IOLockWakeup(l, &other_event, false);
    IOLockUnlock(l);
    sleep_ms(30);
    CHECK(woke.load() == 0);

    IOLockLock(l);
    IOLockWakeup(l, &event, true);
    IOLockUnlock(l);
    CHECK(wait_until([&] { return woke.load() == 1; }, 3000));
    sleep_ms(30);
    CHECK(woke.load() == 1);

    IOLockLock(l);
    IOLockWakeup(l, &event, false);
    IOLockUnlock(l);
    for (size_t i = 0; i < waiters.size(); ++i) waiters[i].join();
    CHECK(woke.load() == 3);
    IOLockFree(l);
}

// ---------------------------------------------------------------------------
// Test 1: setProperties validation
// ---------------------------------------------------------------------------

void test_set_properties_validation() {
    gay_bowser_usbgadget *g = new_gadget();

    CHECK(g->setProperties(NULL) == kIOReturnBadArgument);

    OSString *not_a_dict = OSString::withCString("not a dictionary");
    CHECK(g->setProperties(not_a_dict) == kIOReturnBadArgument);

    OSDictionary *empty = OSDictionary::withCapacity(0);
    CHECK(g->setProperties(empty) == kIOReturnSuccess);
    empty->release();

    // Unknown key: rejected before any state change.
    OSNumber *junk = OSNumber::withNumber(7, 32);
    OSDictionary *unknown = make_props("NoSuchKey", junk);
    CHECK(g->setProperties(unknown) == kIOReturnBadArgument);
    CHECK(g->getProperty("NoSuchKey") == NULL);
    CHECK(g->m_configuration == NULL);
    unknown->release();
    junk->release();

    // Poke is the string value the unprivileged host sends; other types are rejected.
    OSDictionary *bad_poke = make_props("Poke", kOSBooleanTrue);
    CHECK(g->setProperties(bad_poke) == kIOReturnBadArgument);
    bad_poke->release();

    // Non-dictionary PublishConfiguration: rejected, nothing published.
    OSDictionary *bad = make_props("PublishConfiguration", not_a_dict);
    CHECK(g->setProperties(bad) == kIOReturnBadArgument);
    CHECK(g->m_configuration == NULL);
    CHECK(g->getProperty("PublishConfiguration") == NULL);
    bad->release();

    // Valid PublishConfiguration: stored as a private copy, published as given.
    OSDictionary *cfg1 = make_config("first");
    OSDictionary *good1 = make_props("PublishConfiguration", cfg1);
    CHECK(g->setProperties(good1) == kIOReturnSuccess);
    OSDictionary *stored1 = g->m_configuration;
    CHECK(stored1 != NULL);
    CHECK(stored1 != cfg1);
    CHECK(stored1 && stored1->getCount() == cfg1->getCount());
    CHECK(g->getProperty("PublishConfiguration") == cfg1);

    // Duplicate PublishConfiguration: second one replaces the first, the old copy is released.
    OSDictionary *cfg2 = make_config("second");
    OSDictionary *good2 = make_props("PublishConfiguration", cfg2);
    CHECK(g->setProperties(good2) == kIOReturnSuccess);
    CHECK(g->m_configuration != NULL);
    CHECK(g->m_configuration != stored1);
    CHECK(g->getProperty("PublishConfiguration") == cfg2);
    OSString *serial = g->m_configuration ? OSDynamicCast(OSString, g->m_configuration->getObject("serialNumber")) : NULL;
    CHECK(serial && serial->isEqualTo("second"));

    // Invalid value after a valid one: error, previous configuration kept.
    OSDictionary *kept = g->m_configuration;
    OSDictionary *bad2 = make_props("PublishConfiguration", not_a_dict);
    CHECK(g->setProperties(bad2) == kIOReturnBadArgument);
    CHECK(g->m_configuration == kept);
    CHECK(g->getProperty("PublishConfiguration") == cfg2);
    bad2->release();

    // Unknown key alongside a valid configuration: reject before applying it.
    OSNumber *junk2 = OSNumber::withNumber(7, 32);
    OSDictionary *mixed_valid = OSDictionary::withCapacity(2);
    mixed_valid->setObject("PublishConfiguration", cfg2);
    mixed_valid->setObject("NoSuchKey", junk2);
    CHECK(g->setProperties(mixed_valid) == kIOReturnBadArgument);
    CHECK(g->m_configuration == kept);
    CHECK(g->getProperty("PublishConfiguration") == cfg2);
    mixed_valid->release();
    junk2->release();

    // A failed registry publish is reported and does not replace the stored copy.
    OSDictionary *stored_before = g->m_configuration;
    OSObject *published_before = g->getProperty("PublishConfiguration");
    fail_next_set_property();
    OSDictionary *cfg3 = make_config("publish-fail");
    OSDictionary *good3 = make_props("PublishConfiguration", cfg3);
    CHECK(g->setProperties(good3) == kIOReturnNoMemory);
    CHECK(g->m_configuration == stored_before);
    CHECK(g->getProperty("PublishConfiguration") == published_before);
    CHECK(g->setProperties(good3) == kIOReturnSuccess);
    CHECK(g->m_configuration != stored_before);
    CHECK(g->getProperty("PublishConfiguration") == cfg3);
    good3->release();
    cfg3->release();

    // Mixed dictionary: unknown + invalid PublishConfiguration + Poke still reports the bad argument.
    OSDictionary *mixed = OSDictionary::withCapacity(3);
    OSNumber *n = OSNumber::withNumber(1, 32);
    mixed->setObject("NoSuchKey", n);
    mixed->setObject("PublishConfiguration", not_a_dict);
    mixed->setObject("Poke", kOSBooleanTrue);
    CHECK(g->setProperties(mixed) == kIOReturnBadArgument);
    mixed->release();
    n->release();

    // Poke alone, with the host's string value, succeeds.
    OSDictionary *pokeOnly = make_poke_props();
    CHECK(g->setProperties(pokeOnly) == kIOReturnSuccess);
    pokeOnly->release();

    good1->release();
    good2->release();
    cfg1->release();
    cfg2->release();
    not_a_dict->release();
    g->release();
}

// ---------------------------------------------------------------------------
// Test 2: setProperties out-of-memory at every allocation site
// ---------------------------------------------------------------------------

void sweep_set_properties_oom(gay_bowser_usbgadget *g, OSDictionary *props, int min_sites, const char *label) {
    int sites = 0;
    bool completed = false;
    for (unsigned long n = 1; n <= 64; ++n) {
        OSDictionary *cfg_before = g->m_configuration;
        OSObject *published_before = g->getProperty("PublishConfiguration");
        long live_before = g_stats.live_objects.load();

        arm_alloc_failure(n);
        IOReturn r = g->setProperties(props);
        bool fired = alloc_failure_fired();
        disarm_alloc_failure();

        if (!fired) {
            CHECKF(r == kIOReturnSuccess, "%s: setProperties without injected failure returned 0x%x", label, r);
            completed = true;
            break;
        }
        ++sites;
        CHECKF(r == kIOReturnNoMemory, "%s: allocation #%lu failed but setProperties returned 0x%x", label, n, r);
        CHECKF(g->m_configuration == cfg_before, "%s: allocation #%lu failure changed m_configuration", label, n);
        CHECKF(g->getProperty("PublishConfiguration") == published_before,
               "%s: allocation #%lu failure still published PublishConfiguration", label, n);
        CHECKF(g_stats.live_objects.load() == live_before, "%s: allocation #%lu failure leaked %ld object(s)", label, n,
               g_stats.live_objects.load() - live_before);
    }
    CHECKF(completed, "%s: sweep never reached a failure-free run", label);
    CHECKF(sites >= min_sites, "%s: only %d allocation sites exercised (expected >= %d)", label, sites, min_sites);
}

void test_set_properties_oom() {
    gay_bowser_usbgadget *g = new_gadget();

    OSDictionary *cfg = make_config("oom");
    OSDictionary *publish = make_props("PublishConfiguration", cfg);
    // Two symbols + iterator + dictionary copy, first with no prior configuration, then replacing one.
    sweep_set_properties_oom(g, publish, 4, "publish/no-prior-config");
    CHECK(g->m_configuration != NULL);
    sweep_set_properties_oom(g, publish, 4, "publish/replace-config");

    // Poke on a gadget with no configuration: the worker's doUpdate returns early and never allocates, so
    // it cannot consume the armed failure.
    gay_bowser_usbgadget *unconfigured = new_gadget();
    OSDictionary *poke_props = make_poke_props();
    // Two symbols + iterator.
    sweep_set_properties_oom(unconfigured, poke_props, 3, "poke");

    poke_props->release();
    unconfigured->release();
    publish->release();
    cfg->release();
    g->release();
}

// ---------------------------------------------------------------------------
// Test 3: kernel_thread_start failure
// ---------------------------------------------------------------------------

void test_thread_start_failure() {
    // init fails closed when the worker cannot be created; free after the partial
    // init must release the lock and superclass state exactly once.
    fail_next_thread_start();
    gay_bowser_usbgadget *g = new gay_bowser_usbgadget;
    CHECK(!g->init(NULL));
    CHECK(g->m_thread == THREAD_NULL);
    CHECK(g->m_pokeLock == NULL);
    CHECK(g_stats.threads_started.load() == 0);
    CHECK(g_stats.thread_deallocs.load() == 0);
    g->release();
}

// ---------------------------------------------------------------------------
// Test 4: lifecycle permutations
// ---------------------------------------------------------------------------

void test_lifecycle_permutations() {
    // start / stop / free
    {
        FakeController *c = new FakeController;
        gay_bowser_usbgadget *g = new_gadget();
        CHECK(g->start(c));
        CHECK(g->shim_register_calls.load() == 1);
        CHECK(c->getRetainCount() == 2);
        g->stop(c);
        CHECK(c->getRetainCount() == 1);
        CHECK(g->m_thread == THREAD_NULL);
        CHECK(g->m_controller_provider == NULL);
        CHECK(g_stats.thread_deallocs.load() == 1);
        g->release();
        CHECK(c->getRetainCount() == 1);
        c->release();
    }
    // start / free (stop never called): the controller retain must still be dropped.
    {
        FakeController *c = new FakeController;
        gay_bowser_usbgadget *g = new_gadget();
        CHECK(g->start(c));
        CHECK(c->getRetainCount() == 2);
        g->release();
        CHECK(c->getRetainCount() == 1);
        c->release();
    }
    // stop then free, never started
    {
        FakeController *c = new FakeController;
        gay_bowser_usbgadget *g = new_gadget();
        g->stop(c);
        CHECK(c->getRetainCount() == 1);
        CHECK(g->m_thread == THREAD_NULL);
        g->release();
        c->release();
    }
    // double stop
    {
        FakeController *c = new FakeController;
        gay_bowser_usbgadget *g = new_gadget();
        CHECK(g->start(c));
        g->stop(c);
        g->stop(c);
        CHECK(c->getRetainCount() == 1);
        CHECK(g_stats.thread_deallocs.load() == g_stats.threads_started.load());
        g->release();
        c->release();
    }
    // free without start
    {
        gay_bowser_usbgadget *g = new_gadget();
        g->release();
    }
    // free without init (kernel zero-fills the object; m_pokeLock and m_thread are NULL)
    {
        gay_bowser_usbgadget *g = new gay_bowser_usbgadget;
        g->release();
    }
    // start with a NULL provider fails cleanly
    {
        gay_bowser_usbgadget *g = new_gadget();
        CHECK(!g->start(NULL));
        CHECK(g->m_controller_provider == NULL);
        g->stop(NULL);
        g->release();
    }
    // super::start failure: controller retain rolled back, no registerService
    {
        FakeController *c = new FakeController;
        gay_bowser_usbgadget *g = new_gadget();
        fail_next_super_start();
        CHECK(!g->start(c));
        CHECK(c->getRetainCount() == 1);
        CHECK(g->m_controller_provider == NULL);
        CHECK(g->shim_register_calls.load() == 0);
        g->stop(c);
        CHECK(c->getRetainCount() == 1);
        g->release();
        c->release();
    }
    // init failure (every allocation site inside init) then free
    {
        int sites = 0;
        bool completed = false;
        for (unsigned long n = 1; n <= 16; ++n) {
            gay_bowser_usbgadget *g = new gay_bowser_usbgadget;
            long started_before = g_stats.threads_started.load();
            arm_alloc_failure(n);
            bool ok = g->init(NULL);
            bool fired = alloc_failure_fired();
            disarm_alloc_failure();
            if (!fired) {
                CHECK(ok);
                g->release();
                completed = true;
                break;
            }
            ++sites;
            CHECKF(!ok, "init succeeded although allocation #%lu failed", n);
            CHECKF(g_stats.threads_started.load() == started_before, "failed init started a worker (allocation #%lu)", n);
            g->release();
        }
        CHECK(completed);
        CHECKF(sites >= 2, "only %d init allocation sites exercised", sites);
    }
    // super::init failure then free
    {
        gay_bowser_usbgadget *g = new gay_bowser_usbgadget;
        fail_next_super_init();
        CHECK(!g->init(NULL));
        CHECK(g->m_pokeLock == NULL);
        CHECK(g->m_thread == THREAD_NULL);
        g->release();
    }
    CHECK(g_stats.thread_deallocs.load() == g_stats.threads_started.load());
}

// ---------------------------------------------------------------------------
// Test 5: exactly-once teardown under concurrency
// ---------------------------------------------------------------------------

void test_exactly_once_teardown() {
    const int kIterations = 100;
    for (int i = 0; i < kIterations; ++i) {
        FakeController *c = new FakeController;
        gay_bowser_usbgadget *g = new_gadget();

        OSDictionary *cfg = make_config("race");
        OSDictionary *props = make_props("PublishConfiguration", cfg);
        CHECK(g->setProperties(props) == kIOReturnSuccess);
        props->release();
        cfg->release();
        CHECK(g->start(c));

        long deallocs_before = g_stats.thread_deallocs.load();

        std::atomic<bool> go(false), pokers_done(false);
        std::vector<std::thread> stoppers, pokers;
        // One full stop() (single caller, as the kernel guarantees) races with the reaping step that free()
        // performs (stopThread) and with a poke storm.
        stoppers.push_back(std::thread([&] {
            spin_until(go);
            g->stop(c);
        }));
        for (int t = 0; t < 3; ++t) {
            stoppers.push_back(std::thread([&] {
                spin_until(go);
                g->stopThread();
            }));
        }
        for (int t = 0; t < 2; ++t) {
            pokers.push_back(std::thread([&] {
                while (!pokers_done.load()) g->triggerUpdate();
            }));
        }
        go = true;
        for (size_t t = 0; t < stoppers.size(); ++t) stoppers[t].join();
        pokers_done = true;
        for (size_t t = 0; t < pokers.size(); ++t) pokers[t].join();

        CHECKF(g_stats.thread_deallocs.load() - deallocs_before == 1, "iteration %d: worker reaped %ld times", i,
               g_stats.thread_deallocs.load() - deallocs_before);
        CHECK(g->m_thread == THREAD_NULL);
        CHECK(g->m_threadDone);
        CHECK(c->getRetainCount() == 1);
        g->release();  // free() runs stopThread() once more, which must be a no-op
        CHECK(c->getRetainCount() == 1);
        c->release();
        CHECKF(g_stats.thread_deallocs.load() == g_stats.threads_started.load(), "iteration %d: thread leak/double reap", i);
    }
}

// ---------------------------------------------------------------------------
// Test 6: user client
// ---------------------------------------------------------------------------

void test_userclient_init() {
    // NULL task
    {
        gay_bowser_usbgadget_userclient *uc = new gay_bowser_usbgadget_userclient;
        CHECK(!uc->initWithTask(NULL, NULL, 0, NULL));
        CHECK(uc->m_providerLock == NULL);
        CHECK(uc->m_provider == NULL);
        CHECK(poke(uc) == kIOReturnNotReady);
        uc->release();
    }
    // super::initWithTask failure
    {
        gay_bowser_usbgadget_userclient *uc = new gay_bowser_usbgadget_userclient;
        fail_next_super_init_with_task();
        CHECK(!uc->initWithTask(reinterpret_cast<task_t>(static_cast<uintptr_t>(1)), NULL, 0, NULL));
        CHECK(uc->m_providerLock == NULL);
        CHECK(uc->m_provider == NULL);
        uc->release();
    }
    // allocation failure inside super::initWithTask (property dictionary)
    {
        gay_bowser_usbgadget_userclient *uc = new gay_bowser_usbgadget_userclient;
        arm_alloc_failure(1, kAllocDictionary);
        CHECK(!uc->initWithTask(reinterpret_cast<task_t>(static_cast<uintptr_t>(1)), NULL, 0, NULL));
        disarm_alloc_failure();
        CHECK(uc->m_providerLock == NULL);
        uc->release();
    }
    // lock allocation failure
    {
        gay_bowser_usbgadget_userclient *uc = new gay_bowser_usbgadget_userclient;
        arm_alloc_failure(1, kAllocLock);
        CHECK(!uc->initWithTask(reinterpret_cast<task_t>(static_cast<uintptr_t>(1)), NULL, 0, NULL));
        CHECK(alloc_failure_fired());
        disarm_alloc_failure();
        CHECK(uc->m_providerLock == NULL);
        uc->release();
    }
    // free without init (zero-filled, no lock, no provider)
    {
        gay_bowser_usbgadget_userclient *uc = new gay_bowser_usbgadget_userclient;
        CHECK(poke(uc) == kIOReturnNotReady);
        uc->release();
    }
}

void test_userclient_not_ready_and_dispatch() {
    gay_bowser_usbgadget *g = new_gadget();
    gay_bowser_usbgadget_userclient *uc = new_userclient();

    // Poke before start.
    CHECK(poke(uc) == kIOReturnNotReady);

    // Out-of-range selector.
    IOExternalMethodArguments args;
    memset(&args, 0, sizeof(args));
    CHECK(uc->externalMethod(gay_bowser_usbgadget_method_count, &args, NULL, NULL, NULL) == kIOReturnUnsupported);

    // Wrong provider type: start fails and takes no reference on anything.
    IOService *plain = new IOService;
    CHECK(!uc->start(plain));
    CHECK(plain->getRetainCount() == 1);
    CHECK(uc->m_provider == NULL);
    CHECK(poke(uc) == kIOReturnNotReady);
    plain->release();

    // NULL provider.
    CHECK(!uc->start(NULL));
    CHECK(uc->m_provider == NULL);

    // super::start failure takes no reference.
    fail_next_super_start();
    CHECK(!uc->start(g));
    CHECK(g->getRetainCount() == 1);
    CHECK(uc->m_provider == NULL);

    uc->release();
    g->release();
}

void test_userclient_poke_reaches_gadget() {
    FakeController *c = new FakeController;
    gay_bowser_usbgadget *g = new_gadget();
    gay_bowser_usbgadget_userclient *uc = new_userclient();

    OSDictionary *cfg = make_config("poke-serial");
    OSDictionary *props = make_props("PublishConfiguration", cfg);
    CHECK(g->setProperties(props) == kIOReturnSuccess);
    CHECK(g->start(c));
    CHECK(uc->start(g));
    CHECK(g->getRetainCount() == 2);

    CHECK(poke(uc) == kIOReturnSuccess);
    bool reached = wait_until([&] { return c->calls.load() >= 1; }, 3000);
    CHECK(reached);
    if (reached) {
        CHECK(c->command() == "SetDeviceConfiguration");
        CHECK(c->serial() == "poke-serial");
        CHECK(c->param_count() == cfg->getCount());
    }

    uc->clientClose();
    CHECK(poke(uc) == kIOReturnNotReady);
    uc->release();
    CHECK(g->getRetainCount() == 1);
    g->stop(c);
    g->release();
    c->release();
    props->release();
    cfg->release();
}

void run_userclient_sequence(const char *seq) {
    gay_bowser_usbgadget *g = new_gadget();
    gay_bowser_usbgadget_userclient *uc = new_userclient();
    bool held = false;
    for (const char *p = seq; *p; ++p) {
        switch (*p) {
            case 'S':
                CHECKF(uc->start(g), "sequence %s: start failed", seq);
                held = true;
                break;
            case 'T':
                uc->stop(g);
                held = false;
                break;
            case 'C':
                CHECKF(uc->clientClose() == kIOReturnSuccess, "sequence %s: clientClose failed", seq);
                held = false;
                break;
            case 'F':
                uc->release();
                uc = NULL;
                held = false;
                break;
        }
        CHECKF(g->getRetainCount() == (held ? 2 : 1), "sequence %s after '%c': provider refcount %d (expected %d)", seq, *p,
               g->getRetainCount(), held ? 2 : 1);
        if (uc) {
            IOReturn r = poke(uc);
            CHECKF(r == (held ? kIOReturnSuccess : kIOReturnNotReady), "sequence %s after '%c': poke returned 0x%x", seq, *p, r);
        }
    }
    if (uc) uc->release();
    CHECKF(g->getRetainCount() == 1, "sequence %s: provider refcount %d at end", seq, g->getRetainCount());
    g->release();
}

void test_userclient_orderings() {
    static const char *const sequences[] = {"STCF", "SCTF", "SCCTTF", "STTCCF", "SF",    "SCF",
                                            "STF",  "TCSF", "CTSTF",  "F",      "TF",    "CF"};
    for (size_t i = 0; i < sizeof(sequences) / sizeof(sequences[0]); ++i) run_userclient_sequence(sequences[i]);

    // Provider outlives its other owners: the user client holds the last reference and drops it exactly once.
    {
        gay_bowser_usbgadget *g = new_gadget();
        gay_bowser_usbgadget_userclient *uc = new_userclient();
        CHECK(uc->start(g));
        CHECK(g->getRetainCount() == 2);
        g->release();  // harness reference gone; uc keeps the gadget alive
        CHECK(poke(uc) == kIOReturnSuccess);
        CHECK(uc->m_provider != NULL && uc->m_provider->getRetainCount() == 1);
        uc->release();  // free() releases the provider -> gadget freed (checked by the leak accounting)
    }
}

void test_userclient_poke_vs_close() {
    const int kIterations = 200;
    for (int i = 0; i < kIterations; ++i) {
        FakeController *c = new FakeController;
        gay_bowser_usbgadget *g = new_gadget();
        gay_bowser_usbgadget_userclient *uc = new_userclient();
        OSDictionary *cfg = make_config("close-race");
        OSDictionary *props = make_props("PublishConfiguration", cfg);
        CHECK(g->setProperties(props) == kIOReturnSuccess);
        props->release();
        cfg->release();
        CHECK(g->start(c));
        CHECK(uc->start(g));

        std::atomic<bool> go(false), closed(false);
        std::vector<std::thread> pokers;
        for (int t = 0; t < 3; ++t) {
            pokers.push_back(std::thread([&] {
                spin_until(go);
                for (;;) {
                    bool was_closed = closed.load();
                    IOReturn r = poke(uc);
                    if (was_closed) {
                        CHECKF(r == kIOReturnNotReady, "poke after close returned 0x%x", r);
                        break;
                    }
                    CHECKF(r == kIOReturnSuccess || r == kIOReturnNotReady, "poke returned 0x%x", r);
                }
            }));
        }
        std::thread closer([&] {
            spin_until(go);
            for (int k = 0; k < (i % 7) * 20; ++k) std::this_thread::yield();
            if (i % 2 == 0) {
                uc->clientClose();
            } else {
                uc->stop(g);
            }
            closed = true;
        });
        go = true;
        closer.join();
        for (size_t t = 0; t < pokers.size(); ++t) pokers[t].join();

        CHECKF(g->getRetainCount() == 1, "iteration %d: provider refcount %d after close", i, g->getRetainCount());
        uc->release();
        CHECKF(g->getRetainCount() == 1, "iteration %d: provider refcount %d after free", i, g->getRetainCount());
        g->stop(c);
        g->release();
        c->release();
    }
}

// ---------------------------------------------------------------------------
// Test 7: stop waits for an in-flight controller call and does not hold m_pokeLock during it
// ---------------------------------------------------------------------------

void test_stop_waits_for_controller() {
    // A: the worker calls a slow controller outside m_pokeLock; a second poke completes while the
    //    controller is blocked, and stop() waits for the in-flight update before reaping the worker.
    {
        FakeController *c = new FakeController;
        c->block = true;
        c->gate_open = false;
        gay_bowser_usbgadget *g = new_gadget();
        gay_bowser_usbgadget_userclient *uc = new_userclient();
        OSDictionary *cfg = make_config("deadlock");
        OSDictionary *props = make_props("PublishConfiguration", cfg);
        CHECK(g->setProperties(props) == kIOReturnSuccess);
        CHECK(g->start(c));
        CHECK(uc->start(g));
        CHECK(poke(uc) == kIOReturnSuccess);
        CHECK(wait_until([&] { return c->entered.load(); }, 3000));

        std::atomic<bool> stop_done(false), poke_done(false);
        std::thread stopper([&] {
            g->stop(c);
            stop_done = true;
        });
        std::thread second_poke([&] {
            poke(uc);
            poke_done = true;
        });
        sleep_ms(50);
        CHECK(!stop_done.load());  // waits for the in-flight controller call
        CHECK(poke_done.load());   // poke is not serialized behind the controller call
        c->gate_open = true;
        stopper.join();
        second_poke.join();
        CHECK(stop_done.load());
        CHECK(poke_done.load());
        CHECK(g->m_thread == THREAD_NULL);
        CHECK(c->getRetainCount() == 1);

        uc->clientClose();
        uc->release();
        g->release();
        c->release();
        props->release();
        cfg->release();
    }
    // B: the lock is held by an external poke-like critical section; stopThread must wait, then reap.
    {
        gay_bowser_usbgadget *g = new_gadget();
        IOLockLock(g->m_pokeLock);
        std::atomic<bool> done(false);
        std::thread stopper([&] {
            g->stopThread();
            done = true;
        });
        sleep_ms(50);
        CHECK(!done.load());
        IOLockUnlock(g->m_pokeLock);
        stopper.join();
        CHECK(done.load());
        CHECK(g->m_thread == THREAD_NULL);
        CHECK(g->m_threadDone);
        g->release();
    }
    // C: the user client holds the last provider reference while pokes are served; the gadget (with a running
    //    worker) is torn down by the user client's free().
    {
        gay_bowser_usbgadget *g = new_gadget();
        gay_bowser_usbgadget_userclient *uc = new_userclient();
        CHECK(uc->start(g));
        g->release();  // the user client now owns the only reference
        std::atomic<bool> done(false);
        std::thread poker([&] {
            for (int k = 0; k < 200; ++k) poke(uc);
            done = true;
        });
        poker.join();
        CHECK(done.load());
        uc->release();  // final release of the gadget happens in userclient::free()
    }
}

// ---------------------------------------------------------------------------
// Test 7b: a synchronous reentrant controller callback must not deadlock or lose the poke
// ---------------------------------------------------------------------------

void test_controller_reentrancy() {
    FakeController *c = new FakeController;
    gay_bowser_usbgadget *g = new_gadget();
    gay_bowser_usbgadget_userclient *uc = new_userclient();
    OSDictionary *cfg = make_config("reentrant");
    OSDictionary *props = make_props("PublishConfiguration", cfg);
    CHECK(g->setProperties(props) == kIOReturnSuccess);
    CHECK(g->start(c));
    CHECK(uc->start(g));

    std::atomic<int> reentered(0);
    c->on_set_properties = [&] {
        if (reentered.fetch_add(1) == 0) g->triggerUpdate();
    };

    CHECK(poke(uc) == kIOReturnSuccess);
    CHECK(wait_until([&] { return c->calls.load() >= 2; }, 3000));
    CHECK(reentered.load() >= 1);
    CHECK(g_stats.violations.load() == 0);
    CHECK(g->m_thread != THREAD_NULL);

    uc->clientClose();
    g->stop(c);
    uc->release();
    g->release();
    c->release();
    props->release();
    cfg->release();
}

// ---------------------------------------------------------------------------
// Failure sweeps: arm a failure at the nth shim-mediated operation of one kind, for n = 1, 2, ... until a run
// injects nothing, once one-shot (fail once) and once sticky (fail that and every later operation).
// Every trial replays the same fixed scenario in a freshly reset shim world with a trial-specific RNG seed.
// ---------------------------------------------------------------------------

uint64_t base_seed() {
    static const uint64_t seed = []() -> uint64_t {
        const char *env = getenv("KEXT_HARNESS_SEED");
        if (env && *env) return static_cast<uint64_t>(strtoull(env, NULL, 0));
        return 20240601u;
    }();
    return seed;
}

enum SweepStep {
    kStepInit = 1,
    kStepSetProps,
    kStepStart,
    kStepUcInit,
    kStepUcStart,
    kStepWork,
    kStepTeardown
};

enum Teardown { kTeardownStopFree, kTeardownFreeOnly };

struct SweepFixtures {
    OSDictionary *cfg;
    OSDictionary *publish;
};

struct ScenarioResult {
    ScenarioResult()
        : init_ok(false),
          worker_present(false),
          setprops_rc(kIOReturnSuccess),
          config_set(false),
          start_ok(false),
          uc_init_ok(false),
          uc_start_ok(false),
          poke_rc(kIOReturnSuccess),
          settled(true),
          ctrl_calls(0),
          thread_left_after_stop(false) {}
    bool init_ok;
    bool worker_present;
    IOReturn setprops_rc;
    bool config_set;
    bool start_ok;
    bool uc_init_ok;
    bool uc_start_ok;
    IOReturn poke_rc;
    bool settled;
    int ctrl_calls;
    bool thread_left_after_stop;
};

// Fixed scenario: gadget init -> publish config -> start -> user client init/start -> poke (worker pushes the
// configuration into the controller) -> teardown. Only kext code performs shim-mediated operations in here, so
// the per-operation sequence numbers are the same on every run.
void run_scenario(Teardown td, const SweepFixtures &f, ScenarioResult &r) {
    set_step(kStepInit);
    FakeController *c = new FakeController;
    gay_bowser_usbgadget *g = new gay_bowser_usbgadget;
    r.init_ok = g->init(NULL);
    if (!r.init_ok) {
        g->release();
        c->release();
        mark_quiescent();
        return;
    }
    r.worker_present = g->m_thread != THREAD_NULL;

    set_step(kStepSetProps);
    r.setprops_rc = g->setProperties(f.publish);
    r.config_set = g->m_configuration != NULL;

    set_step(kStepStart);
    r.start_ok = g->start(c);

    set_step(kStepUcInit);
    gay_bowser_usbgadget_userclient *uc = new gay_bowser_usbgadget_userclient;
    r.uc_init_ok = uc->initWithTask(reinterpret_cast<task_t>(static_cast<uintptr_t>(1)), NULL, 0, NULL);
    if (r.uc_init_ok) {
        set_step(kStepUcStart);
        r.uc_start_ok = uc->start(g);
    }

    set_step(kStepWork);
    if (r.uc_start_ok) {
        r.poke_rc = poke(uc);
    } else {
        g->triggerUpdate();
    }
    if (r.worker_present) {
        // The worker clears m_needsUpdate once it has finished (or skipped) the update.
        r.settled = wait_until(
            [g] {
                IOLockLock(g->m_pokeLock);
                bool done = !g->m_needsUpdate;
                IOLockUnlock(g->m_pokeLock);
                return done;
            },
            3000);
    }
    set_step(kStepTeardown);
    if (td == kTeardownStopFree) {
        uc->clientClose();
        g->stop(c);
        r.thread_left_after_stop = g->m_thread != THREAD_NULL;
        mark_quiescent();
        uc->release();
        g->release();
    } else {
        uc->release();
        g->release();
        mark_quiescent();
    }
    // The worker is reaped by stop/free, so this is the final controller-call count.
    r.ctrl_calls = c->calls.load();
    c->release();
}

// An injection affects `step` if it fired during that step, or (sticky) during an earlier one.
bool injection_active(bool fired, bool sticky, int fired_step, int step) {
    return fired && (fired_step == step || (sticky && fired_step < step));
}

// Declared acceptable outcomes. Returns false and fills `why` when the scenario result is not one of them.
bool classify(Op op, bool sticky, bool fired, int fired_step, const ScenarioResult &r, char *why, size_t why_len) {
#define EXPECT(cond, ...)                      \
    do {                                       \
        if (!(cond)) {                         \
            snprintf(why, why_len, __VA_ARGS__); \
            return false;                      \
        }                                      \
    } while (0)

    const bool alloc_like = op == kOpAlloc || op == kOpLockAlloc;
    if (fired) {
        const bool step_ok = op == kOpSetProperties ? fired_step == kStepWork
                             : op == kOpThreadStart ? fired_step == kStepInit
                                                    : fired_step >= kStepInit && fired_step <= kStepWork;
        EXPECT(step_ok, "injection fired in unexpected step %d", fired_step);
    }
    EXPECT(r.settled, "worker never finished the pending update");

    // gadget init: every allocation site (properties dictionary, lock) and a failed
    // thread start must fail init; an uninjected run must start a worker.
    const bool init_must_fail =
        injection_active(fired, sticky, fired_step, kStepInit) && (alloc_like || op == kOpThreadStart);
    EXPECT(r.init_ok == !init_must_fail, "init returned %d, expected %d", r.init_ok, !init_must_fail);
    if (!r.init_ok) return true;
    EXPECT(r.worker_present, "init succeeded without a worker");

    // setProperties: every allocation site must surface kIOReturnNoMemory and must not store the configuration.
    const bool props_must_fail = op == kOpAlloc && injection_active(fired, sticky, fired_step, kStepSetProps);
    const IOReturn want_rc = props_must_fail ? kIOReturnNoMemory : kIOReturnSuccess;
    EXPECT(r.setprops_rc == want_rc, "setProperties returned 0x%x, expected 0x%x", r.setprops_rc, want_rc);
    EXPECT(r.config_set == !props_must_fail, "config_set=%d, expected %d", r.config_set, !props_must_fail);

    EXPECT(r.start_ok, "gadget start() failed although it performs no shim-mediated operation that can fail");

    const bool uc_must_fail = alloc_like && injection_active(fired, sticky, fired_step, kStepUcInit);
    EXPECT(r.uc_init_ok == !uc_must_fail, "user client init returned %d, expected %d", r.uc_init_ok, !uc_must_fail);
    if (r.uc_init_ok) {
        EXPECT(r.uc_start_ok, "user client start() failed");
        EXPECT(r.poke_rc == kIOReturnSuccess, "poke returned 0x%x", r.poke_rc);
    }

    // The worker pushes the configuration to the controller exactly once unless an allocation failure
    // makes it skip the update; a failing controller call (kOpSetProperties) is still one call.
    const bool update_skipped = op == kOpAlloc && injection_active(fired, sticky, fired_step, kStepWork);
    const int want_calls = (r.worker_present && r.config_set && !update_skipped) ? 1 : 0;
    EXPECT(r.ctrl_calls == want_calls, "controller saw %d update(s), expected %d", r.ctrl_calls, want_calls);
    EXPECT(!r.thread_left_after_stop, "stop() returned with the worker thread still registered");
    return true;
#undef EXPECT
}

// One trial. Returns false (with `why`) when the outcome or the post-trial accounting is wrong.
bool run_trial(Teardown td, Op op, unsigned long n, bool sticky, uint64_t seed, bool *fired_out, char *why,
               size_t why_len) {
    reset();
    seed_rng(seed);
    // Fixtures are built before arming so the harness's own allocations can never be injected.
    SweepFixtures f;
    f.cfg = make_config("sweep");
    f.publish = make_props("PublishConfiguration", f.cfg);
    const long live_base = g_stats.live_objects.load();
    const long locks_base = g_stats.live_locks.load();
    const long held_base = g_stats.locks_held.load();

    arm_op_failure(op, n, sticky);
    ScenarioResult r;
    run_scenario(td, f, r);
    const bool fired = op_failure_fired(op);
    const int fired_step = op_failure_step(op);
    disarm_op_failures();
    *fired_out = fired;

    bool ok = classify(op, sticky, fired, fired_step, r, why, why_len);
    if (ok) {
        if (g_stats.violations.load() != 0) {
            snprintf(why, why_len, "%ld shim violation(s) (see SHIM VIOLATION lines above)", g_stats.violations.load());
            ok = false;
        } else if (g_stats.post_teardown_ops.load() != 0) {
            snprintf(why, why_len, "%ld shim call(s) from the worker after stop()/free() returned",
                     g_stats.post_teardown_ops.load());
            ok = false;
        } else if (g_stats.live_objects.load() != live_base) {
            snprintf(why, why_len, "leaked %ld object(s)", g_stats.live_objects.load() - live_base);
            ok = false;
        } else if (g_stats.live_locks.load() != locks_base) {
            snprintf(why, why_len, "leaked %ld lock(s)", g_stats.live_locks.load() - locks_base);
            ok = false;
        } else if (g_stats.locks_held.load() != held_base) {
            snprintf(why, why_len, "%ld lock(s) still held at teardown", g_stats.locks_held.load() - held_base);
            ok = false;
        } else if (g_stats.workers_running.load() != 0) {
            snprintf(why, why_len, "%ld worker(s) still running", g_stats.workers_running.load());
            ok = false;
        } else if (g_stats.threads_started.load() != g_stats.thread_deallocs.load()) {
            snprintf(why, why_len, "started %ld thread(s), reaped %ld", g_stats.threads_started.load(),
                     g_stats.thread_deallocs.load());
            ok = false;
        }
    }

    f.publish->release();
    f.cfg->release();
    return ok;
}

bool g_trace_dumped = false;

void run_sweep(const char *scenario, Teardown td, Op op, int min_sites) {
    const uint64_t base = base_seed();
    int trials = 0;
    for (int mode = 0; mode < 2; ++mode) {
        const bool sticky = mode == 1;
        int fired_trials = 0;
        bool terminated = false;
        for (unsigned long n = 1; n <= 128; ++n) {
            const uint64_t seed = base ^ (0x9e3779b97f4a7c15ull * static_cast<uint64_t>(trials + 1));
            char why[256] = "";
            bool fired = false;
            const bool ok = run_trial(td, op, n, sticky, seed, &fired, why, sizeof(why));
            ++trials;
            if (fired) ++fired_trials;
            if (!ok) {
                check_failedf(__LINE__,
                              "sweep %s/%s %s n=%lu: %s [base_seed=%llu trial_seed=%llu; rerun with KEXT_HARNESS_SEED=%llu]",
                              scenario, op_name(op), sticky ? "sticky" : "one-shot", n, why,
                              static_cast<unsigned long long>(base), static_cast<unsigned long long>(seed),
                              static_cast<unsigned long long>(base));
                if (!g_trace_dumped) {
                    g_trace_dumped = true;
                    dump_trace(stderr, 32);
                }
            }
            if (!fired) {
                terminated = true;
                break;
            }
        }
        CHECKF(terminated, "sweep %s/%s %s: still injecting at n=128 (seed=%llu)", scenario, op_name(op),
               sticky ? "sticky" : "one-shot", static_cast<unsigned long long>(base));
        CHECKF(fired_trials >= min_sites, "sweep %s/%s %s: only %d injection site(s) reached (expected >= %d)", scenario,
               op_name(op), sticky ? "sticky" : "one-shot", fired_trials, min_sites);
    }
    printf("sweep %s/%s: %d trials (seed=%llu)\n", scenario, op_name(op), trials, static_cast<unsigned long long>(base));
    fflush(stdout);
}

template <Teardown TD, Op OP, int MIN_SITES>
void test_sweep() {
    run_sweep(TD == kTeardownStopFree ? "stop_free" : "free_only", TD, OP, MIN_SITES);
}

// ---------------------------------------------------------------------------
// Runner: each test in a forked child under a watchdog
// ---------------------------------------------------------------------------

struct TestCase {
    const char *name;
    void (*fn)();
};

const TestCase kTests[] = {
    {"shim_lock_semantics", test_shim_lock_semantics},
    {"1_set_properties_validation", test_set_properties_validation},
    {"2_set_properties_oom", test_set_properties_oom},
    {"3_thread_start_failure", test_thread_start_failure},
    {"4_lifecycle_permutations", test_lifecycle_permutations},
    {"5_exactly_once_teardown", test_exactly_once_teardown},
    {"6a_userclient_init", test_userclient_init},
    {"6b_userclient_not_ready_and_dispatch", test_userclient_not_ready_and_dispatch},
    {"6c_userclient_poke_reaches_gadget", test_userclient_poke_reaches_gadget},
    {"6d_userclient_orderings", test_userclient_orderings},
    {"6e_userclient_poke_vs_close", test_userclient_poke_vs_close},
    {"7_stop_waits_for_controller", test_stop_waits_for_controller},
    {"7b_controller_reentrancy", test_controller_reentrancy},
    {"8a_sweep_stop_free_alloc", test_sweep<kTeardownStopFree, kOpAlloc, 10>},
    {"8b_sweep_stop_free_lock_alloc", test_sweep<kTeardownStopFree, kOpLockAlloc, 2>},
    {"8c_sweep_stop_free_thread_start", test_sweep<kTeardownStopFree, kOpThreadStart, 1>},
    {"8d_sweep_stop_free_set_properties", test_sweep<kTeardownStopFree, kOpSetProperties, 1>},
    {"8e_sweep_free_only_alloc", test_sweep<kTeardownFreeOnly, kOpAlloc, 10>},
    {"8f_sweep_free_only_lock_alloc", test_sweep<kTeardownFreeOnly, kOpLockAlloc, 2>},
    {"8g_sweep_free_only_thread_start", test_sweep<kTeardownFreeOnly, kOpThreadStart, 1>},
    {"8h_sweep_free_only_set_properties", test_sweep<kTeardownFreeOnly, kOpSetProperties, 1>},
};

void run_child(const TestCase &t) {
    reset();
    seed_rng(base_seed());
    g_failed_checks = 0;
    long live_baseline = g_stats.live_objects.load();

    t.fn();

    CHECKF(g_stats.violations.load() == 0, "%ld shim violation(s) reported", g_stats.violations.load());
    CHECKF(g_stats.post_teardown_ops.load() == 0, "%ld shim call(s) from a worker after teardown",
           g_stats.post_teardown_ops.load());
    CHECKF(g_stats.live_objects.load() == live_baseline, "leaked %ld object(s)", g_stats.live_objects.load() - live_baseline);
    CHECKF(g_stats.live_locks.load() == 0, "leaked %ld lock(s)", g_stats.live_locks.load());
    CHECKF(g_stats.locks_held.load() == 0, "%ld lock(s) still held at teardown", g_stats.locks_held.load());
    CHECKF(g_stats.threads_started.load() == g_stats.thread_deallocs.load(), "started %ld thread(s), reaped %ld",
           g_stats.threads_started.load(), g_stats.thread_deallocs.load());
    CHECKF(g_stats.workers_running.load() == 0, "%ld worker(s) still running", g_stats.workers_running.load());

    if (g_failed_checks.load() != 0) {
        fprintf(stderr, "  seed=%llu (override with KEXT_HARNESS_SEED)\n", static_cast<unsigned long long>(base_seed()));
        if (!g_trace_dumped) dump_trace(stderr, 32);
    }
    fflush(stdout);
    fflush(stderr);
    // exit() (not _exit) so sanitizer runtimes apply their failure exit codes.
    exit(g_failed_checks.load() == 0 ? 0 : 1);
}

bool run_test(const TestCase &t, unsigned timeout_seconds) {
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        printf("FAIL %s (fork failed: %s)\n", t.name, strerror(errno));
        return false;
    }
    if (pid == 0) run_child(t);

    std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    int status = 0;
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) break;
        if (r < 0 && errno != EINTR) {
            printf("FAIL %s (waitpid failed: %s)\n", t.name, strerror(errno));
            return false;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            printf("FAIL %s (watchdog: no completion within %us)\n", t.name, timeout_seconds);
            return false;
        }
        usleep(2000);
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("PASS %s\n", t.name);
        return true;
    }
    if (WIFSIGNALED(status)) {
        printf("FAIL %s (killed by signal %d)\n", t.name, WTERMSIG(status));
    } else {
        printf("FAIL %s (exit status %d)\n", t.name, WEXITSTATUS(status));
    }
    return false;
}

}  // namespace

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    unsigned timeout_seconds = 5;
    if (const char *env = getenv("KEXT_HARNESS_TEST_TIMEOUT_SECONDS")) {
        long v = strtol(env, NULL, 10);
        if (v > 0) timeout_seconds = static_cast<unsigned>(v);
    }
    const char *filter = argc > 1 ? argv[1] : NULL;

    int ran = 0, failed = 0;
    for (size_t i = 0; i < sizeof(kTests) / sizeof(kTests[0]); ++i) {
        if (filter && !strstr(kTests[i].name, filter)) continue;
        ++ran;
        if (!run_test(kTests[i], timeout_seconds)) ++failed;
    }
    if (ran == 0) {
        printf("FAIL no test matches '%s'\n", filter ? filter : "");
        return 1;
    }
    printf("%d test(s), %d failed\n", ran, failed);
    return failed == 0 ? 0 : 1;
}
