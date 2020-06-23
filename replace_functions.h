#ifndef _REPLACE_FUNCTIONS_H
#define _REPLACE_FUNCTIONS_H

#include <sstream>
#include <algorithm>

#include "globals.h"

/*
  This set of convience functions can be called from an
  application to interact with the tool. Current we assign taint marks,
  dump taint marks, and control if logging is enabled
 */

void ReplaceUserFunctions(IMG img,void *v);
void DisplayTagsForByteRange(ADDRINT start,size_t size,char *fmt,...);
void AssignTagToByteRange(ADDRINT start,size_t size, size_t id);
void AssignPointerTagToByteRange(ADDRINT start,size_t size, size_t id);
void AssignMemoryTagToByteRange(ADDRINT start,size_t size, size_t id);
void ClearTagsForByteRange(ADDRINT start);
void TagsCheck(ADDRINT pointer, ADDRINT memory);

extern map<string,int> tagMap;
extern vector<ADDRINT> dynMemVector;
void SetTrace(int trace);

#endif
