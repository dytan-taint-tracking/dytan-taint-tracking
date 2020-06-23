#ifndef _TAINT_FUNC_ARGS
#define _TAINT_FUNC_ARGS

#include <cstring>

#include "globals.h"
#include "taint_handling.h"

//this is where the user specifies how to taint function arguments

void taint_routines(RTN ,void *);
void main_wrapper_func(ADDRINT *argcAddr, ADDRINT *argvAddr);

#endif
