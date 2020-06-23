#ifndef _TAINT_SOURCE_FUNC_H
#define _TAINT_SOURCE_FUNC_H

#include "pin.H"

#include <string>
#include <vector>

#include "globals.h"
#include "bitset.h"
#include "taint_generator.h"

/**
 * This class taints the return value of a function. This application
 * is designed for GCC compiler for x86 architecture and hence we are
 * assuming that the code has been compiled using CDECL calling convention.
 * It is not possible to provide a generic function that taints the
 * return value of a function as the way values are returned from a
 * function varies a lot. The following assumptions are made regarding
 * the function return value
 * (http://www.angelcode.com/dev/callconv/callconv.html)
 *
 * 1. Primitive data types, except floating point values, are returned in
 * EAX or EAX:EDX depending on the size.
 * 2. float and double are returned in fp0, i.e. the first floating point
 * register.
 * 3. All structures and classes are returned in memory regardless of
 * complexity or size.
 * 4. When a return is made in memory the caller passes a pointer to
 * the memory location as the first parameter (hidden). The callee
 * populates the memory, and returns the pointer. The callee pops
 * the hidden pointer from the stack when returning.
 * 5. Classes that have a destructor are always passed by reference,
 * even if the parameter is defined to be by value.
 */

class FunctionTaintSource {

 private:
    vector<string> functions;

 public:
    FunctionTaintSource();
    ~FunctionTaintSource();

    void addFunctionSource(string, TaintGenerator *);
    friend VOID ImageLoad(IMG, VOID *);
};

#endif
