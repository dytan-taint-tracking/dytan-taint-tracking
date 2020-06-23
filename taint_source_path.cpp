#include "taint_source_path.h"

PathTaintSource::PathTaintSource(SyscallMonitor *syscallMonitor, bool observeEverything)
{
  monitor = new PathMonitor(syscallMonitor, observeEverything);
  monitor->activate();

  monitor->registerDefault(pathSourceReadDefault, this);
}

PathTaintSource::~PathTaintSource()
{
  delete monitor;
}

void PathTaintSource::addObserverForAll(taint_range_t type)
{
    switch (type) {
        case PerByte:
            monitor->registerCallbackForAll(pathSourceReadCallbackPerByte, NULL);
            break;
        case PerRead:
            monitor->registerCallbackForAll(pathSourceReadCallbackPerRead, NULL);
            break;
        default:
            printf("Missing case\n");
            abort();
    }
}

void PathTaintSource::addPathSource(string pathname, taint_range_t type)
{
  switch(type) {
  case PerByte: {
    monitor->observePath(pathname, pathSourceReadCallbackPerByte, NULL);
    break;
  }
  case PerRead: {
    monitor->observePath(pathname, pathSourceReadCallbackPerRead, NULL);
    break;
  }
  default:
    printf("Missing case\n");
    abort();
  }

}

void pathSourceReadCallbackPerByte(string pathname,
				   syscall_arguments args,
				   void *v)
{
//  TaintGenerator *gen = static_cast<TaintGenerator *>(v);

  char *buf = (char *) args.arg1;
  int ret = args.ret;
  int tag = -1;

  ADDRINT start = (ADDRINT) buf;
  ADDRINT end = start + ret;

  //bail if nothing was actually assigned to memory
  if(ret <= 0) return;

  assert(taintGen);
  bitset *s = bitset_init(NUMBER_OF_TAINT_MARKS);

  for(ADDRINT addr = start; addr < end; addr++) {
      tag = taintGen->nextTaintMark();
      bitset_set_bit(s, tag);
      memTaintMap[addr] = bitset_copy(s);
      bitset_reset(s);
  }
  bitset_free(s);

  lseek(args.arg0, 0, SEEK_CUR);
  //off_t currentOffset = lseek(args.arg0, 0, SEEK_CUR);
  //off_t curr = currentOffset - args.ret;
  //ADDRINT currAddress = start;
  //while (curr != currentOffset) {
  //    taintAssignmentLog << tag << " - " << pathname << "[" << curr++ << "] -> " << std::hex << currAddress++ << "\n";
  //}
  //taintAssignmentLog.flush();


#ifdef TRACE
  if(tracing) {
      log << "\t" << std::hex << start << "-" << std::hex << end - 1 << " <- read\n";
      log.flush();
  }
#endif
}

void pathSourceReadCallbackPerRead(string pathname,
				   syscall_arguments args,
				   void *v)
{
//  TaintGenerator *gen = static_cast<TaintGenerator *>(v);

  char *buf = (char *) args.arg1;
  int ret = args.ret;
  int tag;

  ADDRINT start = (ADDRINT) buf;
  ADDRINT end = start + ret;

  //bail if nothing was actually assigned to memory
  if(ret <= 0) return;

  assert(taintGen);
  bitset *s = bitset_init(NUMBER_OF_TAINT_MARKS);
  tag = taintGen->nextTaintMark();
  bitset_set_bit(s, tag);

  for(ADDRINT addr = start; addr < end; addr++) {
      memTaintMap[addr] = bitset_copy(s);
  }
  bitset_free(s);

  lseek(args.arg0, 0, SEEK_CUR);
  //off_t currentOffset = lseek(args.arg0, 0, SEEK_CUR);
  //taintAssignmentLog << tag << " - " << pathname << "[" << currentOffset - args.ret << "-" << currentOffset << "] -> " << std::hex << start << "-" << std::hex << end -1 << "\n";
  //taintAssignmentLog.flush();

#ifdef TRACE
  if(tracing) {
      log << "\t" << std::hex << start << "-" << std::hex << end - 1 << " <- read(" << tag <<")\n";
      log.flush();
  }
#endif

}

void pathSourceReadDefault(string pathname,
			   syscall_arguments args,
			   void *v)
{
}
