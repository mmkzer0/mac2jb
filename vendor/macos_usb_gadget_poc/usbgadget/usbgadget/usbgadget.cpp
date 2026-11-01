#include <IOKit/IOLib.h>
#include <libkern/OSMalloc.h>

#include "usbgadget.h"
#include "debug.h"

#define super IOService
OSDefineMetaClassAndStructors(gay_bowser_usbgadget, IOService);

// Adding values into the ioreg dictionary
bool
gay_bowser_usbgadget::setDictionaryNumber(const char * symbol,
								 UInt32 value,
								 OSDictionary * dictionary)
{
	if (!dictionary)
		return false;
	OSNumber * number = OSNumber::withNumber(value, 32);
	if (number)
	{
		bool ok = dictionary->setObject(symbol, number);
		number->release();
		return ok;
	}
	return false;
}

bool
gay_bowser_usbgadget::setDictionaryString(const char * symbol,
								 char * value,
								 OSDictionary * dictionary)
{
	if (!value || !dictionary)
		return false;
	OSString * string = OSString::withCString(value);
	if (string)
	{
		bool ok = dictionary->setObject(symbol, string);
		string->release();
		return ok;
	}
	return false;
}

bool
gay_bowser_usbgadget::setDictionaryString(const char * symbol,
								 const char * value,
								 OSDictionary * dictionary)
{
	if (!value || !dictionary)
		return false;
	OSString * string = OSString::withCString(value);
	if (string)
	{
		bool ok = dictionary->setObject(symbol, string);
		string->release();
		return ok;
	}
	return false;
}

bool
gay_bowser_usbgadget::setDictionaryString(const char * symbol,
								 const OSSymbol * value,
								 OSDictionary * dictionary)
{
	if (!value || !dictionary)
		return false;
	return dictionary->setObject(symbol, value);
}

bool
gay_bowser_usbgadget::setDictionaryBoolean(const char * symbol,
								  bool value,
								  OSDictionary * dictionary)
{
	if (!dictionary)
		return false;
	OSBoolean * boolean = value ? kOSBooleanTrue : kOSBooleanFalse;
	if (boolean)
	{
		return dictionary->setObject(symbol, boolean);
	}
	return false;
}

bool
gay_bowser_usbgadget::setDictionaryArray(const char * symbol,
								OSArray * value,
								OSDictionary * dictionary)
{
	if (!value || !dictionary)
		return false;
	return dictionary->setObject(symbol, value);
}

bool
gay_bowser_usbgadget::setDictionaryDictionary(const char * symbol,
									 OSDictionary * value,
									 OSDictionary * dictionary)
{
	if (!value || !dictionary)
		return false;
	return dictionary->setObject(symbol, value);
}

void gay_bowser_usbgadget::triggerUpdate()
{
    //m_commandGate->runCommand(NULL);
    IOLockLock(m_pokeLock);
    m_needsUpdate = true;
    IOLockUnlock(m_pokeLock);
}

// Called by the worker without m_pokeLock held. Snapshot the configuration and
// controller under the lock, then drop it around the provider callback.
void gay_bowser_usbgadget::doUpdate()
{
    OSDictionary *configuration = NULL;
    IOService *controller = NULL;

    IOLockLock(m_pokeLock);
    if (m_exitThreads) {
        m_needsUpdate = false;
        IOLockUnlock(m_pokeLock);
        return;
    }
    configuration = m_configuration;
    if (configuration) configuration->retain();
    controller = m_controller_provider;
    if (controller) controller->retain();
    // Consume the pending update before the external call so a poke that arrives
    // during the callback remains pending. With no controller yet, keep it
    // pending until start() provides one.
    if (!configuration || controller) {
        m_needsUpdate = false;
    }
    IOLockUnlock(m_pokeLock);

    if (!configuration || !controller) {
        if (controller) controller->release();
        if (configuration) configuration->release();
        return;
    }

    OSDictionary* pCommandDict = OSDictionary::withCapacity(1);
    bool built = pCommandDict &&
        setDictionaryString("USBDeviceCommand", "SetDeviceConfiguration", pCommandDict) &&
        setDictionaryDictionary("USBDeviceCommandParameter", configuration, pCommandDict);

    if (built) {
        IOReturn result = controller->setProperties(pCommandDict);
        if (result != kIOReturnSuccess) {
            LogD("Controller setProperties failed in 'gay_bowser_usbgadget:doUpdate()' (0x%x).", result);
        }
    }

    if (pCommandDict) pCommandDict->release();
    controller->release();
    configuration->release();
}

void gay_bowser_usbgadget::threadMain()
{
    IOLockLock(m_pokeLock);
    while (!m_exitThreads)
    {
        if (m_needsUpdate)
        {
            IOLockUnlock(m_pokeLock);
            doUpdate();
            IOLockLock(m_pokeLock);
        }
        IOLockUnlock(m_pokeLock);

        IOSleepWithLeeway(100, 1000);

        IOLockLock(m_pokeLock);
    }
    
    m_threadDone = true;
    IOLockWakeup(m_pokeLock, &m_threadDone, false);
    IOLockUnlock(m_pokeLock);
}

void thread_bootstrap(void* threadArgument, wait_result_t result)
{
    (void)result;
    gay_bowser_usbgadget* driver = (gay_bowser_usbgadget*) threadArgument;
    driver->threadMain();
}

bool gay_bowser_usbgadget::start(IOService *provider) {
    LogD("Executing 'gay_bowser_usbgadget::start()'.");
    
    IOService *controller = OSDynamicCast(IOService, provider);
    if (!controller) {
        return false;
    }
    
    controller->retain();
    IOLockLock(m_pokeLock);
    m_controller_provider = controller;
    IOLockUnlock(m_pokeLock);
    
    if (!super::start(provider)) {
        IOLockLock(m_pokeLock);
        m_controller_provider = NULL;
        IOLockUnlock(m_pokeLock);
        controller->release();
        return false;
    }
    
    LogD("Calling 'gay_bowser_usbgadget:registerService()'.");
    registerService();

    return true;
}

void gay_bowser_usbgadget::stop(IOService *provider) {
    LogD("Executing 'gay_bowser_usbgadget:stop()'.");
    
    stopThread();
    
    if (m_controller_provider) {
        m_controller_provider->release();
        m_controller_provider = NULL;
    }
    
    super::stop(provider);
}

bool gay_bowser_usbgadget::init(OSDictionary *dictionary) {
    LogD("Executing 'gay_bowser_usbgadget:init()'.");
    
    m_controller_provider = NULL;
    m_configuration = NULL;
    m_pokeLock = NULL;
    m_thread = THREAD_NULL;
    m_threadDone = false;
    m_needsUpdate = false;
    m_exitThreads = false;
    
    if (!super::init(dictionary)) {
        return false;
    }

#if 0
    // root.ConfigurationDescriptors[0].Interfaces[0]
    OSArray* pInterfaceArray = OSArray::withCapacity(4);
    pInterfaceArray->setObject(0, OSString::withCString("AppleUSBNCMControl"));
    pInterfaceArray->setObject(1, OSString::withCString("AppleUSBNCMControlAux"));
    pInterfaceArray->setObject(2, OSString::withCString("AppleUSBNCMData"));
    pInterfaceArray->setObject(3, OSString::withCString("AppleUSBNCMDataAux"));
    
    // root.ConfigurationDescriptors[0]
    OSDictionary* pConfigDict = OSDictionary::withCapacity(1);
    setDictionaryNumber("Attributes", 0xE0, pConfigDict);
    setDictionaryNumber("MaxPower", 0, pConfigDict);
    setDictionaryArray("Interfaces", pInterfaceArray, pConfigDict);
    
    // root.ConfigurationDescriptors
    OSArray* pDescArray = OSArray::withCapacity(1);
    pDescArray->setObject(0, pConfigDict);
    
    // root
    OSDictionary* pConfigWrapDict = OSDictionary::withCapacity(1);
    setDictionaryArray("ConfigurationDescriptors", pDescArray, pConfigWrapDict);
    setDictionaryBoolean("AllowMultipleCreates", true, pConfigWrapDict);
    //setDictionaryString("serialNumber", "My Serial", pConfigWrapDict);
    //setDictionaryNumber("productID", 0x1234, pConfigWrapDict);
    
    m_configuration = pConfigWrapDict;


    pInterfaceArray->release();
    pConfigDict->release();
    pDescArray->release();
    //pConfigWrapDict->release();
#endif

    m_pokeLock = IOLockAlloc();
    if (!m_pokeLock) {
        LogD("Failed to allocate lock in 'gay_bowser_usbgadget:init()'.");
        return false;
    }
    
    thread_t thread = THREAD_NULL;
    kern_return_t kr = kernel_thread_start(thread_bootstrap, this, &thread);
    if (kr != KERN_SUCCESS)
    {
        LogD("Failed to start thread in 'gay_bowser_usbgadget:init()' (%x).", kr);
        IOLockFree(m_pokeLock);
        m_pokeLock = NULL;
        return false;
    }
    m_thread = thread;
    
    return true;
}

void gay_bowser_usbgadget::free() {
    LogD("Executing 'gay_bowser_usbgadget:free()'.");
    
    stopThread();
    
    if (m_controller_provider) {
        m_controller_provider->release();
        m_controller_provider = NULL;
    }
    
    if (m_configuration) {
        m_configuration->release();
        m_configuration = NULL;
    }
    
    if (m_pokeLock) {
        IOLockFree(m_pokeLock);
        m_pokeLock = NULL;
    }
    
    super::free();
}

// Stops and reaps the worker exactly once; later or concurrent callers that find
// no thread return without deallocating. Safe when no thread was ever started.
void gay_bowser_usbgadget::stopThread() {
    thread_t thread = THREAD_NULL;
    
    if (m_pokeLock) {
        IOLockLock(m_pokeLock);
        m_needsUpdate = false;
        m_exitThreads = true;
        if (m_thread != THREAD_NULL) {
            // IOLockSleep drops m_pokeLock while asleep and retakes it on wakeup.
            while (!m_threadDone) {
                IOLockSleep(m_pokeLock, &m_threadDone, THREAD_UNINT);
            }
            thread = m_thread;
            m_thread = THREAD_NULL;
        }
        IOLockUnlock(m_pokeLock);
    }
    
    if (thread != THREAD_NULL) {
        thread_deallocate(thread);
    }
}

IOReturn gay_bowser_usbgadget::setProperties(OSObject *props_obj)
{
    OSDictionary *dict = OSDynamicCast(OSDictionary, props_obj);
    if (!dict) {
        return kIOReturnBadArgument;
    }

    const OSSymbol *publish_configuration_string = OSSymbol::withCString("PublishConfiguration");
    const OSSymbol *poke_string = OSSymbol::withCString("Poke");
    if (!publish_configuration_string || !poke_string) {
        if (publish_configuration_string) publish_configuration_string->release();
        if (poke_string) poke_string->release();
        return kIOReturnNoMemory;
    }

    OSCollectionIterator *iter = OSCollectionIterator::withCollection(dict);
    if (!iter) {
        publish_configuration_string->release();
        poke_string->release();
        return kIOReturnNoMemory;
    }

    IOReturn return_value = kIOReturnSuccess;
    OSDictionary *publish_value = NULL;
    bool poke = false;

    // Validate the complete dictionary before changing any state.
    OSObject *raw;
    while ((raw = iter->getNextObject())) {
        const OSSymbol *key = OSDynamicCast(OSSymbol, raw);
        if (!key) {
            return_value = kIOReturnBadArgument;
            break;
        }
        OSObject *obj = dict->getObject(key);
        if (!obj) {
            return_value = kIOReturnBadArgument;
            break;
        }

        if (key->isEqualTo(publish_configuration_string)) {
            publish_value = OSDynamicCast(OSDictionary, obj);
            if (!publish_value) {
                return_value = kIOReturnBadArgument;
                break;
            }
        } else if (key->isEqualTo(poke_string)) {
            // The unprivileged host sends CFSTR("Poke").
            if (!OSDynamicCast(OSString, obj)) {
                return_value = kIOReturnBadArgument;
                break;
            }
            poke = true;
        } else {
            return_value = kIOReturnBadArgument;
            break;
        }
    }
    iter->release();

    // Publish before committing the private copy so a failed registry write
    // leaves both the service property and m_configuration unchanged.
    if (return_value == kIOReturnSuccess && publish_value) {
        OSDictionary *copy = OSDictionary::withDictionary(publish_value);
        if (!copy) {
            return_value = kIOReturnNoMemory;
        } else if (!setProperty(publish_configuration_string, publish_value)) {
            copy->release();
            return_value = kIOReturnNoMemory;
        } else {
            IOLockLock(m_pokeLock);
            OSDictionary *old = m_configuration;
            m_configuration = copy;
            IOLockUnlock(m_pokeLock);
            if (old) old->release();
        }
    }

    if (return_value == kIOReturnSuccess && poke) {
        triggerUpdate();
    }

    publish_configuration_string->release();
    poke_string->release();
    return return_value;
}
