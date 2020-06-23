#include "monitor_path.h"

void openCallback(INT32, syscall_arguments, void *);
void closeCallback(INT32, syscall_arguments, void *);
void readCallback(INT32, syscall_arguments, void *);

PathMonitor::PathMonitor(SyscallMonitor *monitor, bool observeAll)
{
    syscallMonitor = monitor;
    observeEverything = observeAll;
    defaultObserver = NULL;
    allObserver = NULL;
}

PathMonitor::~PathMonitor()
{
  if(NULL != defaultObserver) {
    delete defaultObserver;
  }
  if(allObserver != NULL)
      delete allObserver;
}

void PathMonitor::activate()
{
  syscallMonitor->addObserver(SYS_open, openCallback, this);
  syscallMonitor->addObserver(SYS_close, closeCallback, this);
  syscallMonitor->addObserver(SYS_read, readCallback, this);
}

void PathMonitor::observePath(string pathname,
			 PathMonitorCallback callback,
			 void *v)
{
  observers[pathname].push_back(pair<PathMonitorCallback, void *>(callback, v));
}

void PathMonitor::registerCallbackForAll(PathMonitorCallback callback, void *v)
{
    if(allObserver != NULL)
        delete allObserver;
    allObserver = new pair<PathMonitorCallback, void *>(callback, v);
}

void PathMonitor::registerDefault(PathMonitorCallback callback, void *v)
{
  if(NULL != defaultObserver) {
    delete defaultObserver;
  }
  defaultObserver = new pair<PathMonitorCallback, void *>(callback, v);
}

void PathMonitor::addActiveFileDescriptor(int fd, string pathname)
{
  activeFileDescriptors[fd] = pathname;
}

void PathMonitor::removeActiveFileDescriptor(int fd)
{
  activeFileDescriptors.erase(fd);
}

/**
 * called by the listener for read system call. checks if the
 * read has happened on the file that we are interested in (defaultObserver).
 * if that is the case, it calls the callback for PathTaint
 */
void PathMonitor::notifyForRead(syscall_arguments args)
{
  int fd = (int) args.arg0;

  if(activeFileDescriptors.find(fd) == activeFileDescriptors.end()) {
    return;
  }

  string pathname = activeFileDescriptors[fd];

  if(observers.find(pathname) == observers.end()) {

      if(observeEverything == true) {
          if(allObserver != NULL)
              allObserver->first(pathname, args, allObserver->second);
          return;
      }

      if(NULL != defaultObserver) {
      defaultObserver->first(pathname, args, defaultObserver->second);
    }
    return;
  }

  vector<pair<PathMonitorCallback, void *> > activeObservers = observers[pathname];

  for(vector<pair<PathMonitorCallback, void *> >::iterator iter = activeObservers.begin(); iter != activeObservers.end(); iter++) {
    (*iter).first(pathname, args, (*iter).second);
  }

}

/*********************************************/

// int open(const char *pathname, int flags, mode_t mode);
// friend function that listens for the open system call. This
// is called by the system call monitor. Adds the file descriptor
// of the file that is opened
void openCallback(INT32 syscall_num,
		  syscall_arguments args,
		  void *v)
{
  PathMonitor *pathMonitor = static_cast<PathMonitor *>(v);

  if((int)args.ret == -1) return;

  pathMonitor->addActiveFileDescriptor((int) args.ret, string((const char *)args.arg0));
}

// int close(int fd);
// friend function that listens for the close call. called by
// system call monitor. removes file descriptor of the file
// being close
void closeCallback(INT32 syscall_num,
		   syscall_arguments args,
		   void *v)
{
  PathMonitor *pathMonitor = static_cast<PathMonitor *>(v);

  if((int)args.ret == -1) return;

  pathMonitor->removeActiveFileDescriptor((int) args.arg0);
}

// ssize_t read(int fd, void *buf, size_t count);
// friend function that listens for the read call. called by
// system call monitor.
void readCallback(INT32 syscall_num,
		  syscall_arguments args,
		  void *v)
{
  PathMonitor *pathMonitor = static_cast<PathMonitor *>(v);

  if((int)args.ret == -1) return;

  pathMonitor->notifyForRead(args);

}
