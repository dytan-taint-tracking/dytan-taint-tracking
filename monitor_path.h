#ifndef _MONITOR_PATH_H
#define _MONITOR_PATH_H

#include <string>

#include <syscall.h>

#include "syscall_monitor.h"

typedef void (*PathMonitorCallback)(string, syscall_arguments, void *);

class PathMonitor {

 private:
  SyscallMonitor *syscallMonitor;
  bool observeEverything;
  pair<PathMonitorCallback, void *> *defaultObserver;
  pair<PathMonitorCallback, void *> *allObserver;
  map<string, vector< pair<PathMonitorCallback, void *> > > observers;

  map<int, string> activeFileDescriptors;

  void addActiveFileDescriptor(int, string);
  void removeActiveFileDescriptor(int);
  void notifyForRead(syscall_arguments);

 public:
    PathMonitor(SyscallMonitor *monitor, bool observeAll);
  ~PathMonitor();

  void activate();
  void observePath(string, PathMonitorCallback, void *);
  void registerDefault(PathMonitorCallback, void *);
  void registerCallbackForAll(PathMonitorCallback, void *);

  friend void openCallback(INT32, syscall_arguments, void *);
  friend void closeCallback(INT32, syscall_arguments, void *);
  friend void readCallback(INT32, syscall_arguments, void *);
};

#endif
