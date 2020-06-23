#ifndef _TAINT_HANDLING_H
#define _TAINT_HANDLING_H

#include <fstream>
#include <sstream>

#include "globals.h"

void SetNewTaintForMemory(ADDRINT addr, ADDRINT size, int taint_mark = -1);
void SetNewTaintStart();
void ClearTaintSet(bitset *set, unsigned int opcode);
void TaintForRegister(REG reg, bitset *set, unsigned int opcode);
void TaintForMemory(ADDRINT start, ADDRINT size, REG baseReg, REG indexReg,
		bitset *set, unsigned int opcode,  unsigned int to_profile);
void SetTaintForRegister(REG dest, unsigned int opcode, unsigned int to_profile, int numOfArgs, ...);
void ClearTaintForRegister(REG reg, unsigned int opcode, unsigned int to_profile);
void SetTaintForMemory(ADDRINT start, ADDRINT size, unsigned int opcode, unsigned int to_profile, int numOfArgs, ...);
void ClearTaintForMemory(ADDRINT start, ADDRINT size, unsigned int opcode, unsigned int to_profile);

#endif
