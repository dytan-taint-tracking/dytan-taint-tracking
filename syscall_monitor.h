#ifndef _SYSCALL_MONITOR_H
#define _SYSCALL_MONITOR_H

#include "pin.H"

#include <string.h>
#include <syscall.h>
#include "sys/types.h"

#include <map>
#include <vector>

typedef struct
{
  ADDRINT num;

  ADDRINT arg0;
  ADDRINT arg1;
  ADDRINT arg2;
  ADDRINT arg3;
  ADDRINT arg4;
  ADDRINT arg5;

  ADDRINT ret;
  ADDRINT err;
} syscall_arguments;

typedef void (*SyscallMonitorCallback)(INT32, syscall_arguments, void *);

/*
	SyscallMonitor takes care of the dirty work of handling system calls
	all that you need to do it give it the system call number of monitor
	and a callback that will be called after the system call and give the
	arguments and the return value.  See syscall_monitor.H for the system
	call monitor and also syscall_functions.c for the call back functions.
*/

class SyscallMonitor {

public:
	SyscallMonitor();
	void addObserver(INT32 syscall_number, SyscallMonitorCallback callback,
			void * v);
	void setDefaultObserver(SyscallMonitorCallback callback);
	void beginSyscall(UINT32 tid, INT32 num, ADDRINT arg0, ADDRINT arg1,
			ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5);
	void endSyscall(UINT32 tid, ADDRINT ret, ADDRINT err);

private:
	map<UINT32, syscall_arguments> pendingSyscalls;
	map<INT32, vector<pair<SyscallMonitorCallback, void *> > > observers;
	SyscallMonitorCallback defaultObserver;
	PIN_LOCK syscallLock;

};

#endif
