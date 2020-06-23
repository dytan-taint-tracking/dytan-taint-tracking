#ifndef _TAINT_SOURCE_NETWORK_H
#define _TAINT_SOURCE_NETWORK_H

#include <fstream>
#include <string>
#include <iostream>

#include "globals.h"
#include "taint_source.h"
#include "monitor_network.h"
#include "bitset.h"
#include "taint_generator.h"

void networkReadDefault(NetworkAddress, ADDRINT, size_t, void *);
void networkReadCallbackPerByte(NetworkAddress, ADDRINT, size_t, void *);
void networkReadCallbackPerRead(NetworkAddress, ADDRINT, size_t, void *);

class NetworkTaintSource {

    private:
        NetworkMonitor *monitor;

    public:
        NetworkTaintSource(SyscallMonitor *syscallMonitor, bool observeEverything);
        ~NetworkTaintSource();
        void addObserverForAll(taint_range_t type);
        void addNetworkSource(string, string,  taint_range_t);
};

#endif
