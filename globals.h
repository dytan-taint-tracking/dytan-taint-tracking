#ifndef _GLOBALS_H
#define _GLOBALS_H

#include "pin.H"

#include <map>

#include "bitset.h"
#include "taint_generator.h"

//controls if detailed logging is used
#define TRACE 1
/* controls if registers are considered to propagate taint if they're
   used to access memory.  For example: load [%eax], %eax will propagate
   taint if IMPLICIT is defined and it won't if IMPLICIT is not defined
*/
#define IMPLICIT 1

//map that stores taint marks for memory address, currently this is per byte
extern map<ADDRINT, bitset *> memTaintMap;
//map that stores taint marks for registers
extern map<REG, bitset *> regTaintMap;
//map that stores taint marks active due to control flow
extern map<ADDRINT, bitset *> controlTaintMap;
extern map<string, int> profilingMap;

//global storage to hold taint marks
extern bitset *dest;
extern bitset *src;
extern bitset *eax;
extern bitset *edx;
extern bitset *base;
extern bitset *idx;
extern bitset *eflags;
extern bitset *cnt;

//profiling
extern bool tracing;
extern bool profiling_marks;
extern bool profiling_markop;
extern bool word;
extern int word_size;

//maximum allowable number of taint marks
extern int NUMBER_OF_TAINT_MARKS;
//taint generator
extern TaintGenerator *taintGen;

//array with instrumentation functions
typedef void (*InstrumentFunction)(INS ins, void *v);
extern InstrumentFunction instrument_functions[XED_ICLASS_LAST];

//logging to file
extern ofstream log;
extern ofstream prof_log;
extern ostringstream prof_stream;

#endif
