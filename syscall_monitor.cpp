#include "syscall_monitor.h"

SyscallMonitor::SyscallMonitor() {
	PIN_InitLock(&syscallLock);
}

void SyscallMonitor::addObserver(INT32 syscall_number,
		SyscallMonitorCallback callback, void * v) {
	observers[syscall_number].push_back(
			pair<SyscallMonitorCallback, void *>(callback, v));
}

void SyscallMonitor::setDefaultObserver(SyscallMonitorCallback callback) {
	defaultObserver = callback;
}

void SyscallMonitor::beginSyscall(UINT32 tid, INT32 num, ADDRINT arg0, ADDRINT arg1,
		ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5) {
	PIN_GetLock(&syscallLock, 1);
	pendingSyscalls[tid] = (syscall_arguments ) { (ulong) num, arg0, arg1, arg2, arg3,
					arg4, arg5 };

	PIN_ReleaseLock(&syscallLock);

}

void SyscallMonitor::endSyscall(UINT32 tid, ADDRINT ret, ADDRINT err) {
	PIN_GetLock(&syscallLock, 1);
	syscall_arguments args = pendingSyscalls[tid];
	args.ret = ret;
	args.err = err;

	if (observers.find(args.num) != observers.end()) {

		for (vector<pair<SyscallMonitorCallback, void *> >::iterator iter =
				observers[args.num].begin(); iter != observers[args.num].end();
				iter++) {
			iter->first(args.num, args, iter->second);
		}
	} else {
		if (defaultObserver) {
			defaultObserver(args.num, args, 0);
		}
	}
	PIN_ReleaseLock(&syscallLock);
}
