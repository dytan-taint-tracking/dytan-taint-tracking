#include "taint_source_network.h"

NetworkTaintSource::NetworkTaintSource(SyscallMonitor *syscallMonitor, bool observeEverything)
{
    monitor = new NetworkMonitor(syscallMonitor, observeEverything);
    monitor->activate();
    monitor->registerAddressDefault(networkReadDefault, this);
}

NetworkTaintSource::~NetworkTaintSource()
{
    delete monitor;
}

void NetworkTaintSource::addObserverForAll(taint_range_t type)
{
    switch (type) {
        case PerByte:
            monitor->registerCallbackForAll(networkReadCallbackPerByte, NULL);
            break;
        case PerRead:
            monitor->registerCallbackForAll(networkReadCallbackPerRead, NULL);
            break;
        default:
            cout << "Missing case!";
            abort();
    }
}

void NetworkTaintSource::addNetworkSource(string host_ip, string host_port,
        taint_range_t type)
{
    switch(type) {
        case PerByte:
            monitor->observeAddress(host_ip, host_port, networkReadCallbackPerByte, NULL);
            break;
        case PerRead:
            monitor->observeAddress(host_ip, host_port, networkReadCallbackPerRead, NULL);
            break;
        default:
            cout << "Missing case!";
            abort();
    }
}

void networkReadCallbackPerByte(NetworkAddress networkAddr, ADDRINT start, size_t length, void *v)
{
    int tag;

    assert(taintGen);
    bitset *s = bitset_init(NUMBER_OF_TAINT_MARKS);

    ADDRINT end = start + length;
    for(ADDRINT addr = start; addr < end; addr++) {
        tag = taintGen->nextTaintMark();
        bitset_set_bit(s, tag);
        memTaintMap[addr] = bitset_copy(s);
        bitset_reset(s);
    }
    bitset_free(s);

    //ADDRINT currAddress = start;
    //while (currAddress < end) {
    //    taintAssignmentLog << tag << " - [" << networkAddr.strAddress << "] -> " << std::hex << currAddress++ << "\n";
    //}
    //taintAssignmentLog.flush();

#ifdef TRACE
    if(tracing) {
        log << "\t" << std::hex << start << "-" << std::hex << end - 1 << " <- read\n";
        log.flush();
    }
#endif
}

void networkReadCallbackPerRead(NetworkAddress networkAddr, ADDRINT start, size_t length, void *v)
{
    int tag;
    bitset *s = bitset_init(NUMBER_OF_TAINT_MARKS);
    assert(taintGen);
    tag = taintGen->nextTaintMark();
    //taint entire buffer with 1 mark
    bitset_set_bit(s, tag);

    ADDRINT end = start + length;
    for(ADDRINT addr = start; addr < end; addr++) {
        memTaintMap[addr] = bitset_copy(s);
    }
    bitset_free(s);

    //taintAssignmentLog << tag << " - [" << networkAddr.strAddress << "] -> " << std::hex << start << "-" << std::hex << end - 1<< "\n";
    //taintAssignmentLog.flush();

#ifdef TRACE
    if(tracing) {
        log << "\t" << std::hex << start << "-" << std::hex << end - 1 << " <- read(" << tag << ")\n";
        log.flush();
    }
#endif
}

void networkReadDefault(NetworkAddress networkAddr, ADDRINT start, size_t length, void *v)
{
    //printf("Read from  \n ");
    //clear taint marks
}
