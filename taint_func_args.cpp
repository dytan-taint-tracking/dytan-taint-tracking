#include "taint_func_args.h"

/* forward declarations for wrapper functions */
void main_wrapper_func(ADDRINT *, ADDRINT *);

/* This array holds the function names whose arguments are to be tainted */
string taint_function[] =  { "main", "foo", "bar" };

/* This function is invoked from Dytan. Modify this function to
 * specify custom function wrappers
 */
void taint_routines(RTN rtn, void *v)
{
    string rtn_name = RTN_Name(rtn);

    if (rtn_name == taint_function[0]) {

        RTN_Open(rtn);
        /* This function call inserts main_wrapper_func before the
         * function main is executed. Since main takes two parameters,
         * we have supplied two pairs of
         * IARG_FUNCARG_ENTRYPOINT_REFERENCE, <number>
         */
        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(main_wrapper_func),
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
                IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
                IARG_END);
        RTN_Close(rtn);
    } else if (taint_function[1] == rtn_name) {

        /* Repeat above steps for wrapping this function */
    }
}

/* This is the actual custom function wrapper. It takes in arguments of type
 * ADDRINT, which should be type casted to the original type.
 * The arguments should then be tainted using Dytan's library routines.
 */
void main_wrapper_func(ADDRINT *argcAddr, ADDRINT *argvAddr)
{
    /* typecast the arguments to their original type */
    int argc = (int )*argcAddr;
    char **argv = (char **)*argvAddr;

    /* taint the variables using Dytan library routines */
    /* Arguments: starting address of memory, number of bytes,  */
    /* Third argument is optional; it specifies the taint mark */
    /* If not specified, the taint mark is incremented at every call */
    //SetNewTaintForMemory((ADDRINT)argcAddr, (ADDRINT)sizeof(int), 10);
    SetNewTaintForMemory((ADDRINT)argcAddr, (ADDRINT)sizeof(int));

    //use srlen+1 to include terminator
    for (int i = 0; i < argc; i++) {
        ADDRINT addr = (ADDRINT) &argv[i];
        SetNewTaintForMemory( addr, (ADDRINT)strlen(argv[i]));
    }

    //comment if it is not necessary to update the taint marks space
    //update space for taint marks not related to inputs
    SetNewTaintStart();
}
