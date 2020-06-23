#include "syscall_functions.h"

//Maintain a convienience map of file id -> file names
map<int, string> openFiles;

VOID UnimplementedSystemCall(INT32 num, syscall_arguments args, VOID * v)
{
  //if(SYS_nanosleep == num) return;

  log << "system call " << std::dec << num << " unimplemented\n";
  log.flush();
  abort();
}

VOID Handle_ACCESS(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_ALARM(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_BRK(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_CHMOD(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_CLOSE(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_TGKILL(INT32 num, syscall_arguments args, VOID * v)
{
    //pass
}

VOID Handle_DUP(INT32 num, syscall_arguments args, VOID * v)
{
  int fd1 = (int) args.arg0;
  int fd2 = (int) args.ret;

  openFiles[fd2] = openFiles[fd1];
}

VOID Handle_FCNTL64(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_FLOCK(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}



// Clear taint
VOID Handle_FCNTL(INT32 num, syscall_arguments args, VOID * v)
{
  struct stat64 *buf = (struct stat64 *) args.arg1;
  ADDRINT start = (ADDRINT) buf;
  ADDRINT end = start + sizeof(struct stat64);

  // remove taint
  for(ADDRINT addr = start; addr < end; addr++) {

    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }
}

// Clear taint
VOID Handle_FSTAT(INT32 num, syscall_arguments args, VOID * v)
{
  struct stat64 *buf = (struct stat64 *) args.arg1;
  ADDRINT start = (ADDRINT) buf;
  ADDRINT end = start + sizeof(struct stat64);

  // remove taint
  for(ADDRINT addr = start; addr < end; addr++) {

    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }
}

// Clear taint
VOID Handle_FSTAT64(INT32 num, syscall_arguments args, VOID * v)
{
  struct stat64 *buf = (struct stat64 *) args.arg1;
  ADDRINT start = (ADDRINT) buf;
  ADDRINT end = start + sizeof(struct stat64);

  // remove taint
  for(ADDRINT addr = start; addr < end; addr++) {

    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }
}


VOID Handle_FSYNC(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_FTRUNCATE(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

// Clear taint
VOID Handle_GETDENTS64(INT32 num, syscall_arguments args, VOID * v)
{
  struct dirent64 *dirp = (struct dirent64 *) args.arg1;
  unsigned int count = (unsigned int) args.arg2;

  ADDRINT start = (ADDRINT) dirp;
  ADDRINT end = start + count;

  for(ADDRINT addr = start; addr < end; addr++) {

    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }
}

VOID Handle_GETPID(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_GETTID(INT32 num, syscall_arguments args, VOID * v)
{
    //pass
}

// Clear taint
VOID Handle_GETTIMEOFDAY(INT32 num, syscall_arguments args, VOID * v)
{
  struct timeval *tv = (struct timeval *) args.arg0;
  ADDRINT tv_start = (ADDRINT) tv;
  ADDRINT tv_end = tv_start + sizeof(struct timeval);

  for(ADDRINT addr = tv_start; addr < tv_end; addr++) {
    //remove taint from addr
    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }

  struct timezone *tz = (struct timezone *) args.arg1;
  ADDRINT tz_start = (ADDRINT) tz;
  ADDRINT tz_end = tz_start + sizeof(struct timezone);

  for(ADDRINT addr = tz_start; addr < tz_end; addr++) {
    //remove taint from addr
    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }

}

VOID Handle_GETUID(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_IOCTL(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_LINK(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

// Clear taint
VOID Handle_LSEEK(INT32 num, syscall_arguments args, VOID * v)
{
	  struct stat64 *buf = (struct stat64 *) args.arg1;
	  ADDRINT start = (ADDRINT) buf;
	  ADDRINT end = start + sizeof(struct stat64);

	  for(ADDRINT addr = start; addr < end; addr++) {
	    //remove taint from addr
	    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

	    if(memTaintMap.end() != iter) {
	      bitset_free(iter->second);
	      memTaintMap.erase(iter);
	    }
	  }
}

// Clear taint
VOID Handle_LSTAT(INT32 num, syscall_arguments args, VOID * v)
{
  struct stat64 *buf = (struct stat64 *) args.arg1;
  ADDRINT start = (ADDRINT) buf;
  ADDRINT end = start + sizeof(struct stat64);

  for(ADDRINT addr = start; addr < end; addr++) {
    //remove taint from addr
    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }
}

// Clear taint
VOID Handle_MMAP(INT32 num, syscall_arguments args, VOID * v)
{
  ADDRINT start = (ADDRINT) args.ret;
  ADDRINT end = start + (size_t) args.arg1;

  for(ADDRINT addr = start; addr < end; addr++) {
    //remove taint from addr
     map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }
}

// Clear taint
VOID Handle_MMAP2(INT32 num, syscall_arguments args, VOID * v)
{
  ADDRINT start = (ADDRINT) args.ret;
  ADDRINT end = start + (size_t) args.arg1;

  for(ADDRINT addr = start; addr < end; addr++) {
    //remove taint from addr
     map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }
}

VOID Handle_MUNMAP(INT32 num, syscall_arguments args, VOID * v)
{
}

VOID Handle_MPROTECT(INT32 num, syscall_arguments args, VOID * v)
{
}

VOID Handle_OPEN(INT32 num, syscall_arguments args, VOID * v)
{

  openFiles[args.ret] = (const char *) args.arg0;
}


/*
  The read system call taints memory from the start of the second parameter
  to the start of the second parameter + the return value
 */
VOID Handle_READ(INT32 num, syscall_arguments args, VOID * v)
{

    // read call is now handled in PathSourceclass
}


// Clear taint
VOID Handle_READLINK(INT32 num, syscall_arguments args, VOID * v)
{
  char *buf = (char *) args.arg1;
  int ret = args.ret;

  ADDRINT start = (ADDRINT) buf;
  ADDRINT end = start + ret;

  for(ADDRINT addr = start; addr < end; addr++) {
    //remove taint from addr
    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }

  }
}

VOID Handle_RENAME(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}


// Clear taint
VOID Handle_RT_SIGACTION(INT32 num, syscall_arguments args, VOID * v)
{
  struct sigaction *oldact = (struct sigaction *) args.arg2;

  if(NULL != oldact) {
    ADDRINT start = (ADDRINT) oldact;
    ADDRINT end = start + sizeof(struct sigaction);

    for(ADDRINT addr = start; addr < end; addr++) {
      //remove taint from addr
      map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

      if(memTaintMap.end() != iter) {
	bitset_free(iter->second);
	memTaintMap.erase(iter);
      }
    }
  }
}


// Clear taint
VOID Handle_RT_SIGPROCMASK(INT32 num, syscall_arguments args, VOID * v)
{
  sigset_t *oldset = (sigset_t *) args.arg2;

  if(NULL != oldset) {
    ADDRINT start = (ADDRINT) oldset;
    ADDRINT end = start + sizeof(sigset_t);

    for(ADDRINT addr = start; addr < end; addr++) {
      //remove taint from addr
      map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

      if(memTaintMap.end() != iter) {
	bitset_free(iter->second);
	memTaintMap.erase(iter);
      }
    }
  }
}

VOID Handle_SET_THREAD_AREA(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_SOCKET(INT32 num, syscall_arguments args, VOID * v)
{
    switch((int) args.arg0) {
        case SYS_SOCKET:
            //pass
            break;
        case SYS_CONNECT:
            break;
        case SYS_BIND:
        case SYS_LISTEN:
        case SYS_ACCEPT:
        case SYS_GETSOCKNAME:
        case SYS_GETPEERNAME:
        case SYS_SEND:
        case SYS_RECV:
        case SYS_SENDTO:
        case SYS_RECVFROM:
        case SYS_SHUTDOWN:
        case SYS_SETSOCKOPT:
        case SYS_GETSOCKOPT:
        case SYS_SENDMSG:
        case SYS_RECVMSG:
            break;
        default:
            log << "Unhandled socketcall " << args.arg0 <<"\n";
            log.flush();
            abort();
    }
}

// Clear taint
VOID Handle_STAT(INT32 num, syscall_arguments args, VOID * v)
{
  struct stat64 *buf = (struct stat64 *) args.arg1;
  ADDRINT start = (ADDRINT) buf;
  ADDRINT end = start + sizeof(struct stat64);

  for(ADDRINT addr = start; addr < end; addr++) {
    //remove taint from addr
    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }
}

// Clear taint
VOID Handle_TIME(INT32 num, syscall_arguments args, VOID * v)
{
  time_t *t = (time_t *) args.arg0;
  if(NULL != t) {
    ADDRINT start = (ADDRINT) t;
    ADDRINT end = start + sizeof(time_t);

    for(ADDRINT addr = start; addr < end; addr++) {
      //remove taint from addr
      map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

      if(memTaintMap.end() != iter) {
	bitset_free(iter->second);
	memTaintMap.erase(iter);
      }
    }
  }
}

// Clear taint
VOID Handle_UNAME(INT32 num, syscall_arguments args, VOID * v)
{
  struct utsname *buf = (struct utsname *) args.arg0;

  ADDRINT start = (ADDRINT) buf;
  ADDRINT end = start + sizeof(struct utsname);

  for(ADDRINT addr = start; addr < end; addr++) {
    //remove taint from addr
    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);

    if(memTaintMap.end() != iter) {
      bitset_free(iter->second);
      memTaintMap.erase(iter);
    }
  }
}

VOID Handle_UNLINK(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_UTIME(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_WRITE(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_WRITEV(INT32 num, syscall_arguments args, VOID * v)
{
  //pass
}

VOID Handle_POLL(INT32 num, syscall_arguments args, VOID *v)
{
    //TODO
}

VOID Handle_GETGID(INT32 num, syscall_arguments args, VOID * v)
{
	//pass
}

VOID Handle_GETEUID(INT32 num, syscall_arguments args, VOID * v)
{
	//pass
}

VOID Handle_GETEGID(INT32 num, syscall_arguments args, VOID * v)
{
	//pass
}

VOID Handle_GETDENTS(INT32 num, syscall_arguments args, VOID * v)
{
	//pass
}

VOID Handle_CLONE(INT32 num, syscall_arguments args, VOID * v)
{
	//pass
}

VOID Handle_DUP2(INT32 num, syscall_arguments args, VOID * v)
{
	//pass
}

VOID Handle_WAITID(INT32 num, syscall_arguments args, VOID * v)
{
	//pass
}

VOID Handle_SET_TID_ADDRESS(INT32 num, syscall_arguments args, VOID * v)
{
	//pass
}

VOID Handle_CHOWN(INT32 num, syscall_arguments args, VOID * v)
{
	//pass
}
