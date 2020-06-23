#ifndef _MONITOR_NETWORK_H
#define _MONITOR_NETWORK_H

#include <string>
#include <iostream>
#include <sstream>
#include <string>
#include <typeinfo>
#include <map>
#include <stdexcept>
#include <cassert>

#include <syscall.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include "syscall_monitor.h"

struct NetworkAddress {
    uint32_t ip;
    short port;
    string strAddress;
};

typedef void (*NetworkMonitorCallback)(NetworkAddress, ADDRINT, size_t, void *);

// Function object that implements LESS_THAN for type NetworkAddress
struct NetworkAddress_cmp {
    // return true if networkaddress a is less than networkaddress b
    bool operator()(const NetworkAddress &a, const NetworkAddress &b) {
        return (a.ip < b.ip) || (a.port < b.port);
    }
};

class NetworkMonitor {

    private:
        SyscallMonitor *syscallMonitor;
        bool observeEverything;
        pair<NetworkMonitorCallback, void *> *defaultAddressObserver;
        pair<NetworkMonitorCallback, void *> *allObserver;
        map<NetworkAddress, vector<pair<NetworkMonitorCallback, void *> >, NetworkAddress_cmp > addressObservers;
        map<uint32_t, NetworkAddress> socketToAddress;
        void notifyForRead(syscall_arguments, NetworkAddress& , ADDRINT , size_t );

    public:
        NetworkMonitor(SyscallMonitor *syscallMonitor, bool observeAll);
        ~NetworkMonitor();

        void activate();
        void registerAddressDefault(NetworkMonitorCallback, void *);
        void registerCallbackForAll(NetworkMonitorCallback callback, void *v);

        void observeAddress(string, string, NetworkMonitorCallback, void *);

        friend void socketcallNetworkCallback(INT32, syscall_arguments, void *);
        friend void readNetworkCallback(INT32, syscall_arguments, void *);
        friend void closeNetworkCallback(INT32, syscall_arguments, void *);
};

#endif
