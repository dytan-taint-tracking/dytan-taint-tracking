#ifndef _SYSCALL_FUNCTIONS_H
#define _SYSCALL_FUNCTIONS_H

#include <fstream>

#include <sys/stat.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <linux/net.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globals.h"
#include "syscall_monitor.h"

extern map<int,string>openFiles;

//list of syscall numbers at /usr/include/i386-linux-gnu/asm/unistd_32.h

VOID Handle_WRITEV(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_WRITE(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_UTIME(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_UNLINK(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_UNAME(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_TIME(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_STAT(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_SOCKET(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_SET_THREAD_AREA(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_RT_SIGPROCMASK(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_RT_SIGACTION(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_RENAME(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_READLINK(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_READ(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_OPEN(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_MUNMAP(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_MPROTECT(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_MMAP(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_LSTAT(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_LSEEK(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_LINK(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_IOCTL(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_GETUID(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_GETTIMEOFDAY(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_GETPID(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_GETDENTS64(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_FTRUNCATE(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_FSYNC(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_FCNTL(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_FSTAT(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_FSTAT64(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_FLOCK(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_FCNTL64(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_DUP(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_CLOSE(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_CHMOD(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_BRK(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_ALARM(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_ACCESS(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_POLL(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_GETTID(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_TGKILL(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_GETGID(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_GETEUID(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_GETEGID(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_GETDENTS(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_CLONE(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_DUP2(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_WAITID(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_SET_TID_ADDRESS(INT32 num, syscall_arguments args, VOID * v);
VOID Handle_CHOWN(INT32 num, syscall_arguments args, VOID * v);
VOID UnimplementedSystemCall(INT32 num,syscall_arguments args,VOID *v);
VOID Handle_MMAP2(INT32 num,syscall_arguments args,VOID *v);
#endif
