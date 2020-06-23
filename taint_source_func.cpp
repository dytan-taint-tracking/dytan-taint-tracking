#include "taint_source_func.h"

void taint_return_val() {
}

// Called every time a new image is loaded and looks for routines that we want to probe
VOID ImageLoad(IMG img, VOID *v){
    FunctionTaintSource *myself = static_cast<FunctionTaintSource *>(v);
    vector<string>::iterator iter = myself->functions.begin();
    while ( iter != myself->functions.end()) {
        string s = *iter;
        RTN rout = RTN_FindByName(img, (CHAR *)s.c_str());
        if (RTN_Valid(rout)) {
            RTN_InsertCall(rout, IPOINT_AFTER, AFUNPTR(taint_return_val));
        }
        iter++;
    }
}

FunctionTaintSource::FunctionTaintSource(){
    IMG_AddInstrumentFunction(ImageLoad, (VOID *)this);
}

FunctionTaintSource::~FunctionTaintSource(){
}

void FunctionTaintSource::addFunctionSource(string funcName, TaintGenerator *gen){
    //add function name to vector
    functions.push_back(funcName);
}

/*
// Called every time a new image is loaded
// Look for routines that we want to probe
VOID FunctionTaintSource::ImageLoad(IMG img, VOID *v)
{
    vector<string>::iterator iter = functions.begin();
    while ( iter != functions.end()) {
        RTN rout = RTN_FindByName(img, *iter);
        if (RTN_Valid(rout)) {
            // do something
        }
        iter++;
    }
}*/
