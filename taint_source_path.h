#ifndef _TAINT_SOURCE_PATH_H
#define _TAINT_SOURCE_PATH_H

#include <string>

#include "unistd.h"

#include <fstream>
#include <stdio.h>
#include <assert.h>

#include "globals.h"
#include "taint_source.h"
#include "monitor_path.h"
#include "bitset.h"
#include "taint_generator.h"

void pathSourceReadDefault(string, syscall_arguments, void *);
void pathSourceReadCallbackPerByte(string, syscall_arguments, void *);
void pathSourceReadCallbackPerRead(string, syscall_arguments, void *);

class PathTaintSource {

private:
	PathMonitor *monitor;

public:
	PathTaintSource(SyscallMonitor *syscallMonitor, bool observeEverything);
	~PathTaintSource();
	void addPathSource(string, taint_range_t);
	void addObserverForAll(taint_range_t type);

};

#endif
