#include "instrument_opcodes.h"

//bitmasks for accessing specific parts of eflags register
#define CF_MASK 1 << 1
#define PF_MASK 1 << 2
#define AF_MASK 1 << 4
#define ZF_MASK 1 << 6
#define SF_MASK 1 << 7
#define OF_MASK 1 << 11

VOID UnimplementedInstruction(INS ins, VOID * v)
{
  log << "opcode " << INS_Disassemble(ins) << " unimplemented\n";
  log.flush();
  abort();
  //log << INS_Disassemble(ins) << "\n";
  //log.flush();
  //fprintf(log, "%s unimplemented[%d]\n", INS_Disassemble(ins).c_str(),
  //INS_Opcode(ins));
  //prof_log << "opcode:" << std::dec << INS_Opcode(ins) << "\n";
  //prof_log << INS_Disassemble(ins) << "\n";
  //prof_log.flush();
  //abort();
}

ADDRINT CheckCMOVNB(ADDRINT eflags)
{
  return ((eflags & CF_MASK) == 0);
}

ADDRINT CheckCMOVB(ADDRINT eflags)
{
  return ((eflags & CF_MASK) == 1);
}

ADDRINT CheckCMOVBE(ADDRINT eflags)
{
  return (((eflags & CF_MASK) == 1) || ((eflags & ZF_MASK) == 1));
}

ADDRINT CheckCMOVNLE(ADDRINT eflags)
{
  return ((eflags & ZF_MASK) == 0) && ((eflags & SF_MASK) == 0);
}

ADDRINT CheckCMOVNL(ADDRINT eflags)
{
  return ((eflags & SF_MASK) == (eflags & OF_MASK));
}

ADDRINT CheckCMOVL(ADDRINT eflags)
{
  return ((eflags & SF_MASK) != (eflags & OF_MASK));
}

ADDRINT CheckCMOVLE(ADDRINT eflags)
{
  return (((eflags & ZF_MASK) == 1) || ((eflags & SF_MASK) != (eflags & OF_MASK)));
}

ADDRINT CheckCMOVNBE(ADDRINT eflags)
{
  return ((eflags & CF_MASK) == 0) && ((eflags & ZF_MASK) == 0);
}

ADDRINT CheckCMOVNZ(ADDRINT eflags)
{
  return ((eflags & ZF_MASK) == 0);
}

ADDRINT CheckCMOVNO(ADDRINT eflags)
{
  return ((eflags & OF_MASK) == 0);
}

ADDRINT CheckCMOVNP(ADDRINT eflags)
{
  return ((eflags & PF_MASK) == 0);
}

ADDRINT CheckCMOVNS(ADDRINT eflags)
{
  return ((eflags & SF_MASK) == 0);
}

ADDRINT CheckCMOVO(ADDRINT eflags)
{
  return ((eflags & OF_MASK) == 1);
}

ADDRINT CheckCMOVP(ADDRINT eflags)
{
  return ((eflags & PF_MASK) == 1);
}

ADDRINT CheckCMOVS(ADDRINT eflags)
{
  return ((eflags & SF_MASK) == 1);
}

ADDRINT CheckCMOVZ(ADDRINT eflags)
{
  return ((eflags & ZF_MASK) == 1);
}

//CMPXCHG check functions
ADDRINT CheckEqual_r_r(ADDRINT v1, ADDRINT v2)
{
  return v1 == v2;
}

ADDRINT CheckNotEqual_r_r(ADDRINT v1, ADDRINT v2)
{
  return v1 != v2;
}

ADDRINT CheckEqual_m_r(ADDRINT start, ADDRINT size, ADDRINT v2)
{
  ADDRINT v1 = *((ADDRINT *) start);
  return v1 == v2;
}

ADDRINT CheckNotEqual_m_r(ADDRINT start, ADDRINT size, ADDRINT v2)
{
  ADDRINT v1 = *((ADDRINT *) start);
  return v1 == v2;
}

VOID Instrument_ADC(INS ins, VOID *v)
{
  // Insert calls that copy the taint marks associated with the
  // destination argument into the global storage of dest
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {

    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
    log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
    log.flush();
    abort();
  }

  // Insert calls that copy the taint marks associated with the
  // source argument into the global storage of src
  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 1)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else if(INS_OperandIsImmediate(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
    abort();
  }

  // Insert calls that copy the taint marks associated with the
  // eflags into the global storage of eflags
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_PTR, eflags,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  //TPS

  // Insert function call to propagate taint marks from dest, src, eflags
  // to dest.
  //dest <- dest, src, eflags
  if(INS_OperandIsReg(ins, 0)) {

	//taint propagation
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
           IARG_UINT32, 3,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_PTR, eflags,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryWrite(ins)) return;

    //taint propagation
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
           IARG_UINT32, 3,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_PTR, eflags,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
    abort();
  }

  //taint propagation, could be removed and added to code above
  // Insert call to propagate taint marks from dest, src, eflags to eflags
  //eflags <- dest, src, eflags
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 0,
         IARG_UINT32, 3,
		 IARG_PTR, dest,
		 IARG_PTR, src,
		 IARG_PTR, eflags,
		 IARG_END);
}

/*   This is a good example of how instructions are modeled and taint is
 propagated in dytan. To implement one of these functions the first
 thing to do is decide how taint marks should be propagated. In this instance,
 for ADD, the destination operand and the eflags register
 are tainted with the union of the taint marks associated with the
 destination and source operands.

 dest, eflags <- union(dest, src)

 Then the general implementation goes like this
 1. load the taint marks associated with the operands on the right hand
 side of the equation (dest, src)
 2. figure out the union
 3. assign the union to the operands on the left hand side (dest, eflags)
 */

VOID Instrument_ADD(INS ins, VOID *v)
{

  // Figure out what type (register, immediate, memory) the destination
  // operand is.  According to the IA-32 developer's manual the only
  // possibilities are register or memory

  // INS_OperandIsReg is Pin's function to check if an operand is a register
  // for the add instruction we know that 0 (second operand) corresponds
  // to the destination operand.  This may not be true for later versions of
  // Pin which is why we require a specific version.
  if(INS_OperandIsReg(ins, 0)) {

    // If the operand is a register insert a call before the instruction
    // to load the taint marks currently associated with the register into
    // the dest region of memory.

    // In dytan.cpp there are a few global memory regions that are used
    // to pass taint marks around at runtime.  The names correspond to
    // common operand names (dest, src, cnt, eflagsm ...)
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }

  // Similar to above but now we check if the destination is a memory reference
  else if(INS_OperandIsMemory(ins, 0)) {
    // Needs to have a second check here to account for cases
    // where Pin can not calculate memory addresses that use certain memory
    // selectors.  (i.e. Pin know that the operand is a memory reference
    // but can't figure out exactly what memory is being accessed.  In this
    // case we bail since we need to know what memory is read/written
    if(!INS_IsMemoryRead(ins)) return;

    // Load the taint marks currently associated with the read memory area
    // into dest
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
    abort();
  }

  // Do the same thing for the source operand as for the destination operand.
  // Here we have three possibilities, register, memory, or immediate

  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 1)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else if(INS_OperandIsImmediate(ins, 1)) {
    // If the operand is an immediate, by definition, it doesn't have taint
    // but since src is a shared global it may have a residual value so
    // clear it just to make sure.
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
    abort();
  }

  //TPS

  // Assign the union of dest and src to dest.
  // SetTaintForRegister and SetTaintForMemory take a NULL terminate list
  // of taint mark sets, unions them, and assigns the result to its first
  // argument

  //dest <- dest, src

  // Since the destination can be either a register or a memory location
  // handle each case appropriatly
  if(INS_OperandIsReg(ins, 0)) {

	//taint propagation
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
           IARG_UINT32, 2,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryWrite(ins)) return;

	//taint propagation
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_UINT32, 2,
           IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_END);

  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
    abort();
  }

  // Assign the union to the eflags register.

  //taint propagation
  //eflags <- dest, src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 0,
         IARG_UINT32, 2,
		 IARG_PTR, dest,
		 IARG_PTR, src,
		 IARG_END);
}

VOID Instrument_AND(INS ins, VOID *v)
{
  Instrument_ADD(ins, v);
}

VOID Instrument_BSWAP(INS ins, VOID *v)
{
  //pass
}

VOID Instrument_CALL_NEAR(INS ins, VOID *v)
{
  //TODO
}

VOID Instrument_CDQ(INS ins, VOID *v)
{
  UINT32 operandWidth = INS_OperandWidth(ins, 0);
  if(32 == operandWidth) {

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EAX,
		   IARG_PTR, eax,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    //TPS

    // edx <- eax
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EDX,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
           IARG_UINT32, 1,
		   IARG_PTR, eax,
		   IARG_END);

  }
  else {
    log << "Unhandled operand size: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }
}

VOID Instrument_CLD(INS ins, VOID *v)
{

  //TPS

  //eflags <- clear
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
		 IARG_END);
}

VOID Instrument_CMOVcc(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 1)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  xed_iclass_enum_t opcode = (xed_iclass_enum_t) INS_Opcode(ins);

  // CF == 0
  if(XED_ICLASS_CMOVNB == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVNB),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // CF == 1
  else if(XED_ICLASS_CMOVB == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVB),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // CF == 1 || ZF == 1
  else if(XED_ICLASS_CMOVBE == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVBE),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // ZF == 0 && SF == OF
  else if(XED_ICLASS_CMOVNLE == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVNLE),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // SF == OF
  else if(XED_ICLASS_CMOVNL == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVNL),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // SF != OF
  else if(XED_ICLASS_CMOVL == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVL),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // ZF == 1 || SF != OF
  else if(XED_ICLASS_CMOVLE == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVLE),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // CF == 0 && ZF == 0
  else if(XED_ICLASS_CMOVNBE == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVNBE),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // ZF == 0
  else if(XED_ICLASS_CMOVNZ == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVNZ),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // OF == 0
  else if(XED_ICLASS_CMOVNO == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVNO),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // PF == 0
  else if(XED_ICLASS_CMOVNP == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVNP),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // SF == 0
  else if(XED_ICLASS_CMOVNS == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVNS),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // OF == 1
  else if(XED_ICLASS_CMOVO == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVO),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // PF == 1
  else if(XED_ICLASS_CMOVP == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVP),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // SF == 1
  else if(XED_ICLASS_CMOVS == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVS),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }

  // ZF == 1
  else if(XED_ICLASS_CMOVZ == opcode) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckCMOVZ),
		     IARG_REG_VALUE, LEVEL_BASE::REG_EFLAGS,
		     IARG_END);
  }
  else {
    log << "Unhandled cmov type: "<< INS_Disassemble(ins) << "\n";
    log.flush();
    abort();
  }

  //TPS

  //dest <- src
  INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, INS_OperandReg(ins, 0),
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
         IARG_UINT32, 1,
		 IARG_PTR, src,
		 IARG_END);

}

VOID Instrument_CMP(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 1)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else if(INS_OperandIsImmediate(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //TPS

  //eflags <- dest, src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
         IARG_UINT32, 2,
		 IARG_PTR, dest,
		 IARG_PTR, src,
		 IARG_END);
}

VOID Instrument_CMPSB(INS ins, VOID *v)
{
  //Memory reference [edi]
  if(!INS_IsMemoryRead(ins)) return;
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		 IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		 IARG_ADDRINT, LEVEL_BASE::REG_EDI,
		 IARG_ADDRINT, LEVEL_BASE::REG_INVALID,
		 IARG_PTR, dest,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
		 IARG_END);

  //Memory reference [esi]
  if(!INS_IsMemoryRead(ins)) return;
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		 IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE,
		 IARG_ADDRINT, LEVEL_BASE::REG_ESI,
		 IARG_ADDRINT, LEVEL_BASE::REG_INVALID,
		 IARG_PTR, src,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
		 IARG_END);

  //TPS

  //eflags <- dest, src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
         IARG_UINT32, 2,
		 IARG_PTR, dest,
		 IARG_PTR, src,
		 IARG_END);
}

VOID Instrument_CMPXCHG(INS ins, VOID *v)
{
  UINT32 operandWidth = INS_OperandWidth(ins, 0);
  if(32 == operandWidth) {
    if(INS_OperandIsReg(ins, 0)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		     IARG_ADDRINT, INS_OperandReg(ins, 0),
		     IARG_PTR, dest,
			 IARG_UINT32, INS_Opcode(ins),
		     IARG_END);
    }
    else if(INS_OperandIsMemory(ins, 0)) {
      if(!INS_IsMemoryRead(ins)) return;

      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		     IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		     IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		     IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		     IARG_PTR, dest,
			 IARG_UINT32, INS_Opcode(ins),
			 IARG_UINT32, 1,
		     IARG_END);
    }
    else {
        log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
        log.flush();
        abort();
    }

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 2),
		   IARG_PTR, eax,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
    log << "Unhanded operand width: " << operandWidth << " for " << INS_Disassemble(ins) << "\n";
    log.flush();
    abort();
  }

  //TPS

  /*
    if(eax == dest) {
      dest = src
    }
    else {
      eax = src
    }
  */

  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckEqual_r_r),
		     IARG_REG_VALUE, INS_OperandReg(ins, 0),
		     IARG_REG_VALUE, INS_OperandReg(ins, 2),
		     IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		       IARG_ADDRINT, INS_OperandReg(ins, 0),
		       IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
               IARG_UINT32, 1,
		       IARG_PTR, src,
		       IARG_END);

    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckNotEqual_r_r),
		     IARG_REG_VALUE, INS_OperandReg(ins, 0),
		     IARG_REG_VALUE, INS_OperandReg(ins, 2),
		     IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		       IARG_ADDRINT, INS_OperandReg(ins, 2),
		       IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
               IARG_UINT32, 1,
		       IARG_PTR, src,
		       IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckEqual_m_r),
		     IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		     IARG_REG_VALUE, INS_OperandReg(ins, 2),
		     IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_UINT32, 1,
           IARG_PTR, src,
		   IARG_END);

    INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(CheckNotEqual_m_r),
		     IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		     IARG_REG_VALUE, INS_OperandReg(ins, 2),
		     IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		       IARG_ADDRINT, INS_OperandReg(ins, 2),
		       IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
               IARG_UINT32, 1,
		       IARG_PTR, src,
		       IARG_END);

  }
}

VOID Instrument_CWDE(INS ins, VOID *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_AX,
		 IARG_PTR, dest,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  //TPS

  // eax <- ax
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EAX,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
         IARG_UINT32, 1,
		 IARG_PTR, dest,
		 IARG_END);
}

VOID Instrument_DEC(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
    abort();
  }

  //TPS

  //eflags <- dest
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
         IARG_UINT32, 1,
		 IARG_PTR, dest,
		 IARG_END);
}

VOID Instrument_DIV(INS ins, VOID *v)
{
  UINT32 operandWidth = INS_OperandWidth(ins, 0);

  if(32 == operandWidth) {
    if(INS_OperandIsReg(ins, 0)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		     IARG_ADDRINT, INS_OperandReg(ins, 0),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
		     IARG_END);
    }
    else if(INS_OperandIsMemory(ins, 0)) {
      if(!INS_IsMemoryRead(ins)) return;

      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		     IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		     IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		     IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
			 IARG_UINT32, 1,
		     IARG_END);
    }
    else {
        log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
        log.flush();
        abort();
    }

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EAX,
		   IARG_PTR, eax,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EDX,
		   IARG_PTR, edx,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    //TPS

    //eax <- eax, edx, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EAX,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
           IARG_UINT32, 3,
		   IARG_PTR, eax,
		   IARG_PTR, edx,
		   IARG_PTR, src,
		   IARG_END);

    //edx <- eax, edx, src
    //this is 0 because I do not need to compute the clear again however I miss information in destination logging
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EDX,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 0,
           IARG_UINT32, 3,
		   IARG_PTR, eax,
		   IARG_PTR, edx,
		   IARG_PTR, src,
		   IARG_END);

    //eflags <- clear
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
    log << "Unhandled operand size: "<<INS_Disassemble(ins) << "\n";
      log.flush();
    abort();
  }

}

VOID Instrument_FLDCW(INS ins, VOID *v)
{
  //pass
}

VOID Instrument_FLDZ(INS ins, VOID *v)
{
    //pass
}

VOID Instrument_FNSTCW(INS ins, VOID *v)
{

  //TPS

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForMemory),
		 IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
		 IARG_END);
}

VOID Instrument_CPUID(INS ins, VOID *v)
{

	//TPS

    // eax <- clear
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
            IARG_ADDRINT, LEVEL_BASE::REG_EAX,
            IARG_UINT32, INS_Opcode(ins),
            IARG_UINT32, 1,
            IARG_END);
    // ebx <- clear
    //this is 0 because I do not need to compute the clear again however I miss information in destination logging
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
            IARG_ADDRINT, LEVEL_BASE::REG_EBX,
            IARG_UINT32, INS_Opcode(ins),
            IARG_UINT32, 0,
            IARG_END);

    // ecx <- clear
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
            IARG_ADDRINT, LEVEL_BASE::REG_ECX,
            IARG_UINT32, INS_Opcode(ins),
            IARG_UINT32, 0,
            IARG_END);

    // edx <- clear
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
            IARG_ADDRINT, LEVEL_BASE::REG_EDX,
            IARG_UINT32, INS_Opcode(ins),
            IARG_UINT32, 0,
            IARG_END);
}

VOID Instrument_BSF(INS ins, VOID *v)
{

	//TPS

    //erase destination register
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
		   IARG_END);
}

VOID Instrument_BSR(INS ins, VOID *v)
{
	//TPS

    //erase destination register
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
		   IARG_END);
}

VOID Instrument_BT(INS ins, VOID *v)
{
    //TODO : check
}

VOID Instrument_HLT(INS ins, VOID *v)
{
  //pass
}

VOID Instrument_IDIV(INS ins, VOID *v)
{
  UINT32 operandWidth = INS_OperandWidth(ins, 0);

  if(32 == operandWidth) {

    if(INS_OperandIsReg(ins, 0)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		     IARG_ADDRINT, INS_OperandReg(ins, 0),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
		     IARG_END);
    }
    else if(INS_OperandIsMemory(ins, 0)) {
      if(!INS_IsMemoryRead(ins)) return;

      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		     IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		     IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		     IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
			 IARG_UINT32, 1,
		     IARG_END);
    }
    else {
        log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
        log.flush();
        abort();
    }

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EDX,
		   IARG_PTR, edx,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EAX,
		   IARG_PTR, eax,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    //TPS

    // eax <- edx, eax, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EAX,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 3,
		   IARG_PTR, eax,
		   IARG_PTR, edx,
		   IARG_PTR, src,
		   IARG_END);

    // edx <- edx, eax, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EDX,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 0,
           IARG_UINT32, 3,
		   IARG_PTR, eax,
		   IARG_PTR, edx,
		   IARG_PTR, src,
		   IARG_END);

    //eflags <- clear
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
		   IARG_END);
  }
  else {
    log << "Unhanded operand width: " << operandWidth << " for " << INS_Disassemble(ins) << "\n";
    log.flush();
    abort();
  }
}

VOID Instrument_MUL(INS ins, VOID *v)
{
  UINT32 operandWidth = INS_OperandWidth(ins, 0);

  if(32 == operandWidth) {
    if(INS_OperandIsReg(ins, 0)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		     IARG_ADDRINT, INS_OperandReg(ins, 0),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
		     IARG_END);
    }
    else if(INS_OperandIsMemory(ins, 0)) {
      if(!INS_IsMemoryRead(ins)) return;

      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		     IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		     IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		     IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
			 IARG_UINT32, 1,
		     IARG_END);
    }
    else {
        log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
        log.flush();
        abort();
    }

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EAX,
		   IARG_PTR, eax,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);


    //TPS

    //eax <- eax, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EAX,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 2,
		   IARG_PTR, eax,
		   IARG_PTR, src,
		   IARG_END);

    //edx <- eax, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EDX,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 0,
           IARG_UINT32, 2,
		   IARG_PTR, eax,
		   IARG_PTR, src,
		   IARG_END);

    //eflags <- eax, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 0,
           IARG_UINT32, 2,
		   IARG_PTR, eax,
		   IARG_PTR, src,
		   IARG_END);
  }
  else {
    log << "Unhanded operand width: " << operandWidth << " for " << INS_Disassemble(ins) << "\n";
    log.flush();
    abort();
  }
}

VOID Instrument_IMUL(INS ins, VOID *v)
{
  int operand_count = 0;
  for(unsigned int i = 0; i < INS_OperandCount(ins); i++) {
    if(!INS_OperandIsImplicit(ins, i)) operand_count++;
  }

  if(1 == operand_count) {
    Instrument_MUL(ins, v);
  }
  else if(2 == operand_count) {

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    if(INS_OperandIsReg(ins, 1)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		     IARG_ADDRINT, INS_OperandReg(ins, 0),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
		     IARG_END);
    }
    else if(INS_OperandIsMemory(ins, 1)) {
      if(!INS_IsMemoryRead(ins)) return;

      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		     IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		     IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		     IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
			 IARG_UINT32, 1,
		     IARG_END);
    }
    else if(INS_OperandIsImmediate(ins, 1)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
		     IARG_END);
    }
    else {
        log << "Unknown operand type: " << INS_Disassemble(ins) << "\n";
        log.flush();
      abort();
    }

    //TPS

    //dest <- dest, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 2,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_END);

    //eflags <- dest, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 0,
           IARG_UINT32, 2,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_END);
  }
  else if(3 == operand_count) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    if(INS_OperandIsReg(ins, 1)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		     IARG_ADDRINT, INS_OperandReg(ins, 0),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
		     IARG_END);
    }
    else if(INS_OperandIsMemory(ins, 1)) {
      if(!INS_IsMemoryRead(ins)) return;

      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		     IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		     IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		     IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		     IARG_PTR, src,
			 IARG_UINT32, INS_Opcode(ins),
			 IARG_UINT32, 1,
		     IARG_END);
    }
    else {
        log << "Unknown operand type: " << INS_Disassemble(ins) << "\n";
        log.flush();
        abort();
    }

    //TPS

    //dest <- dest, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 2,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_END);

    //eflags <- dest, src
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 0,
           IARG_UINT32, 2,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_END);

  }
  else {
    printf("\tStrange IMUL %s %d\n",
	   INS_Disassemble(ins).c_str(), operand_count);
    abort();
  }
}

VOID Instrument_INC(INS ins, VOID *v)
{
  Instrument_DEC(ins, v);
}

VOID Instrument_INT(INS ins, VOID *v)
{
  //pass
}

VOID Instrument_Jcc(INS ins, VOID *v)
{
  //TODO
}

VOID Instrument_JMP(INS ins, VOID *v)
{
  //PASS
}

VOID Instrument_LEA(INS ins, VOID *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		 IARG_PTR, base,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		 IARG_PTR, idx,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  //TPS

  // dest <- base, idx
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, INS_OperandReg(ins, 0),
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
         IARG_UINT32, 2,
		 IARG_PTR, base,
		 IARG_PTR, idx,
		 IARG_END);
}

VOID Instrument_LEAVE(INS ins, VOID *v)
{
  //TODO
}

VOID Instrument_LDMXCSR(INS ins, VOID *v)
{
  //pass
}

VOID Instrument_MOV(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 1)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else if(INS_OperandIsImmediate(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //TPS

  //dest <- src
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 1,
		   IARG_PTR, src,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
#ifdef IMPLICIT
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_PTR, base,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, idx,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
#endif
    if(!INS_IsMemoryWrite(ins)) return;
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
#ifdef IMPLICIT
           IARG_UINT32, 3,
//#elif
#else
           IARG_UINT32, 1,
#endif
           IARG_PTR, src,
#ifdef IMPLICIT
		   IARG_PTR, base,
		   IARG_PTR, idx,
#endif
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }
}

VOID Instrument_MOVS(INS ins, VOID *v)
{


    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
                   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
                   IARG_ADDRINT, LEVEL_BASE::REG_ESI,
                   IARG_ADDRINT, LEVEL_BASE::REG_INVALID,
                   IARG_PTR, dest,
          		   IARG_UINT32, INS_Opcode(ins),
          		   IARG_UINT32, 1,
                   IARG_END);

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
                   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
                   IARG_ADDRINT, LEVEL_BASE::REG_EDI,
                   IARG_ADDRINT, LEVEL_BASE::REG_INVALID,
                   IARG_PTR, src,
          		   IARG_UINT32, INS_Opcode(ins),
          		   IARG_UINT32, 1,
                   IARG_END);


    if(INS_HasRealRep(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
                       IARG_ADDRINT, LEVEL_BASE::REG_ECX,
                       IARG_PTR, cnt,
              		   IARG_UINT32, INS_Opcode(ins),
                       IARG_END);

        //TPS

        //dest <- edi, esi, ecx
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
                   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
                   IARG_UINT32, INS_Opcode(ins),
                   IARG_UINT32, 1,
                   IARG_UINT32, 3,
                   IARG_PTR, src,
                   IARG_PTR, dest,
                   IARG_PTR, cnt,
                   IARG_END);
    }else {

    	//TPS

        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
                       IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
                       IARG_UINT32, INS_Opcode(ins),
                       IARG_UINT32, 1,
                       IARG_UINT32, 2,
                       IARG_PTR, src,
                       IARG_PTR, dest,
                       IARG_END);

    }

}

VOID Instrument_MOVSB(INS ins, VOID *v)
{
    Instrument_MOVS(ins, v);
}

VOID Instrument_MOVSD(INS ins, VOID *v)
{
    Instrument_MOVS(ins, v);
}

VOID Instrument_MOVSD_XMM(INS ins, VOID *v)
{
	  if(INS_OperandIsReg(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 1)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else if(INS_OperandIsImmediate(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  //TPS

	  //dest <- src
	  if(INS_OperandIsReg(ins, 0)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_UINT32, INS_Opcode(ins),
	           IARG_UINT32, 1,
	           IARG_UINT32, 1,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	#ifdef IMPLICIT
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
			   IARG_PTR, base,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
			   IARG_PTR, idx,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	#endif
	    if(!INS_IsMemoryWrite(ins)) return;
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
			   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
			   IARG_UINT32, INS_Opcode(ins),
	           IARG_UINT32, 1,
	#ifdef IMPLICIT
	           IARG_UINT32, 3,
	//#elif
	#else
	           IARG_UINT32, 1,
	#endif
	           IARG_PTR, src,
	#ifdef IMPLICIT
			   IARG_PTR, base,
			   IARG_PTR, idx,
	#endif
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }
}

VOID Instrument_MOVSW(INS ins, VOID *v)
{
  Instrument_MOVS(ins, v);
}

VOID Instrument_MOVSX(INS ins, VOID *v)
{
  Instrument_MOV(ins, v);
}

VOID Instrument_MOVZX(INS ins, VOID *v)
{
  Instrument_MOV(ins, v);
}

VOID Instrument_NEG(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //TPS

  //eflags <- dest
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
         IARG_UINT32, 1,
		 IARG_PTR, dest,
		 IARG_END);
}

VOID Instrument_NOT(INS ins, VOID *v)
{
  //pass
}

VOID Instrument_OR(INS ins, VOID *v)
{
  Instrument_AND(ins, v);
}

VOID Instrument_PAUSE(INS ins, VOID *v)
{
  //pass
}

VOID Instrument_NOP(INS ins, VOID *v)
{
    //pass -- this instruction doesn't change anything
}

VOID Instrument_POP(INS ins, VOID *v)
{
  if(!INS_IsMemoryRead(ins)) return;

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		 IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		 IARG_ADDRINT, LEVEL_BASE::REG_INVALID,
		 IARG_ADDRINT, LEVEL_BASE::REG_INVALID,
		 IARG_PTR, src,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
		 IARG_END);

  //TPS

  //dest <- src
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 1,
		   IARG_PTR, src,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
#ifdef IMPLICIT
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_PTR, base,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, idx,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
#endif

    if(!INS_IsMemoryWrite(ins)) return;
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
#ifdef IMPLICIT
           IARG_UINT32, 3,
//#elif
#else
           IARG_UINT32, 1,
#endif
           IARG_PTR, src,
#ifdef IMPLICIT
		   IARG_PTR, base,
		   IARG_PTR, idx,
#endif
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }
}

VOID Instrument_POPFD(INS ins, VOID *v)
{
  if(!INS_IsMemoryRead(ins)) return;

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		 IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		 IARG_ADDRINT, LEVEL_BASE::REG_INVALID,
		 IARG_ADDRINT, LEVEL_BASE::REG_INVALID,
		 IARG_PTR, src,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
		 IARG_END);

  //eflags <- top of stack

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_PTR, src,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);
}

VOID Instrument_PUSH(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else if(INS_OperandIsImmediate(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  if(!INS_IsMemoryWrite(ins)) return;

  //TPS

  // dest <- src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		 IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
         IARG_UINT32, 1,
		 IARG_PTR, src,
		 IARG_END);
}

VOID Instrument_PUSHFD(INS ins, VOID *v)
{

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_PTR, src,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  //TPS

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		 IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
         IARG_UINT32, 1,
		 IARG_PTR, src,
		 IARG_END);

}

//for instructions that compare real numbers and set the eflags register
VOID Instrument_Eflags(INS ins, VOID *v)
{
    //TODO:
}

VOID Instrument_SAHF(INS ins, VOID *v)
{
    //TODO
}

VOID Instrument_LAHF(INS ins, VOID *v)
{
    //TODO
}


VOID Instrument_RDTSC(INS ins, VOID *v)
{

  //TPS

  // eax <- clear
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EAX,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
		 IARG_END);

  // edx <- clear
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EDX,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 0,
		 IARG_END);
}

VOID Instrument_RET_NEAR(INS ins, VOID *v)
{
  //TODO
}

VOID Instrument_SAR(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, cnt,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsImmediate(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		   IARG_PTR, cnt,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //TPS

  //dest <- dest, count
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 2,
		   IARG_PTR, dest,
		   IARG_PTR, cnt,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryWrite(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
		   IARG_UINT32, 2,
           IARG_PTR, dest,
		   IARG_PTR, cnt,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //eflags <- dest, count
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 0,
         IARG_UINT32, 2,
		 IARG_PTR, dest,
		 IARG_PTR, cnt,
		 IARG_END);
}

VOID Instrument_SBB(INS ins, VOID *v)
{
  Instrument_ADC(ins, v);
}

VOID Instrument_SCASB(INS ins, VOID *v)
{
  //Memory reference [edi]
  if(!INS_IsMemoryRead(ins)) return;

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		 IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		 IARG_ADDRINT, LEVEL_BASE::REG_EDI,
		 IARG_ADDRINT, LEVEL_BASE::REG_INVALID,
		 IARG_PTR, src,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_UINT32, 1,
		 IARG_END);

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_AL,
		 IARG_PTR, eax,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  //TPS

  //eflags <- src, al
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
         IARG_UINT32, 2,
		 IARG_PTR, src,
		 IARG_PTR, eax,
		 IARG_END);

  if(INS_RepPrefix(ins) || INS_RepnePrefix(ins)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, LEVEL_BASE::REG_ECX,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 0,
           IARG_UINT32, 2,
		   IARG_PTR, src,
		   IARG_PTR, eax,
		   IARG_END);
  }

}

VOID Instrument_SETcc(INS ins, VOID *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_PTR, src,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  //TPS

  //dest <- src
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 1,
           IARG_PTR, src,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryWrite(ins)) return;

#ifdef IMPLICIT
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_PTR, base,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, idx,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
#endif

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
#ifdef IMPLICIT
           IARG_UINT32, 3,
//#elif
#else
           IARG_UINT32, 1,
#endif
		   IARG_PTR, base,
#ifdef IMPLICIT
		   IARG_PTR, idx,
		   IARG_PTR, src,
#endif
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }
}

VOID Instrument_SHL(INS ins, VOID *v)
{
  Instrument_SAR(ins, v);
}

VOID Instrument_SHLD(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, INS_OperandReg(ins, 1),
		 IARG_PTR, cnt,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  if(INS_OperandIsReg(ins, 2)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsImmediate(ins, 2)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //TPS

  //dest <- dest, src, count
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 3,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_PTR, cnt,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryWrite(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 3,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_PTR, cnt,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //eflags <- dest, src, count
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 0,
         IARG_UINT32, 3,
		 IARG_PTR, dest,
		 IARG_PTR, src,
		 IARG_PTR, cnt,
		 IARG_END);
}


VOID Instrument_SHR(INS ins, VOID *v)
{
  Instrument_SAR(ins, v);
}

VOID Instrument_SHRD(INS ins, VOID *v)
{
  Instrument_SHLD(ins, v);
}

VOID Instrument_STD(INS ins, VOID *v)
{
  //TPS

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
		 IARG_END);
}

VOID Instrument_STMXCSR(INS ins, VOID *v)
{
  //TPS

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForMemory),
		 IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
		 IARG_END);
}

VOID Instrument_STOSB(INS ins, VOID *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_AL,
		 IARG_PTR, eax,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
	 IARG_ADDRINT, LEVEL_BASE::REG_EDI,
		 IARG_PTR, src,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  if(!INS_IsMemoryWrite(ins)) return;

  //TPS

  //dest <- edi, al
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		 IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
#ifdef IMPLICIT
         IARG_UINT32, 2,
//#elif
#else
         IARG_UINT32, 1,
#endif
		 IARG_PTR, eax,
#ifdef IMPLICIT
		 IARG_PTR, src,
#endif
		 IARG_END);
}

VOID Instrument_STOSD(INS ins, VOID *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_AX,
		 IARG_PTR, eax,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EDI,
		 IARG_PTR, src,
		 IARG_UINT32, INS_Opcode(ins),
		 IARG_END);

  //TPS

  //dest <- edi, al
  if(!INS_IsMemoryWrite(ins)) return;

  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		 IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
#ifdef IMPLICIT
        IARG_UINT32, 2,
//#elif
#else
        IARG_UINT32, 1,
#endif
		 IARG_PTR, eax,
#ifdef IMPLICIT
		 IARG_PTR, src,
#endif
		 IARG_END);
}

VOID Instrument_SUB(INS ins, VOID *v)
{
  Instrument_ADD(ins, v);
}

VOID Instrument_TEST(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsImmediate(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //TPS

  //eflags <- dest, src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
         IARG_UINT32, 2,
		 IARG_PTR, dest,
		 IARG_PTR, src,
		 IARG_END);
}

VOID Instrument_XADD(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
    abort();
  }

  //TPS

  //dest <- dest, src
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 2,
		   IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryWrite(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
		   IARG_UINT32, 2,
           IARG_PTR, dest,
		   IARG_PTR, src,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //src <- dest
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, INS_OperandReg(ins, 1),
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 1,
         IARG_UINT32, 1,
		 IARG_PTR, dest,
		 IARG_END);

  //eflags <- dest, src
  //because already computed in if then else
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 0,
         IARG_UINT32, 2,
		 IARG_PTR, dest,
		 IARG_PTR, src,
		 IARG_END);
}

VOID Instrument_XCHG(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 1)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //TPS

  //dest <- src
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 1,
		   IARG_PTR, src,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryWrite(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
		   IARG_UINT32, 1,
           IARG_PTR, src,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //src <- dest
  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 1,
		   IARG_PTR, dest,
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 1)) {
    if(!INS_IsMemoryWrite(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
		   IARG_UINT32, 1,
           IARG_PTR, dest,
		   IARG_END);
  }
  else {
      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }
}

VOID Instrument_XOR(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 0)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else if(INS_OperandIsMemory(ins, 1)) {
    if(!INS_IsMemoryRead(ins)) return;

    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
		   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
		   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
		   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_UINT32, 1,
		   IARG_END);
  }
  else if(INS_OperandIsImmediate(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //TPS

  if(INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)
     && INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1)) {

    //dest <- clear
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
		   IARG_END);
  }
  else {
    //dest <- dest, src
    if(INS_OperandIsReg(ins, 0)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		     IARG_ADDRINT, INS_OperandReg(ins, 0),
		     IARG_UINT32, INS_Opcode(ins),
	         IARG_UINT32, 1,
             IARG_UINT32, 2,
		     IARG_PTR, dest,
		     IARG_PTR, src,
		     IARG_END);
    }
    else if(INS_OperandIsMemory(ins, 0)) {
      if(!INS_IsMemoryWrite(ins)) return;

      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
		     IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
		     IARG_UINT32, INS_Opcode(ins),
	         IARG_UINT32, 1,
		     IARG_UINT32, 2,
             IARG_PTR, dest,
		     IARG_PTR, src,
		     IARG_END);
    }
    else {
        log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
        log.flush();
        abort();
    }
  }

  //eflags <- dest, src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_UINT32, INS_Opcode(ins),
         IARG_UINT32, 0,
         IARG_UINT32, 2,
		 IARG_PTR, dest,
		 IARG_PTR, src,
		 IARG_END);

}
/*
VOID Instrument_DAA(INS ins, VOID *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_AL,
		 IARG_PTR, src,
		 IARG_END);

  //eflags <- src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_PTR, src,
		 IARG_END);

}

VOID Instrument_DAS(INS ins, VOID *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_AL,
		 IARG_PTR, src,
		 IARG_END);

  //eflags <- src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_PTR, src,
		 IARG_END);

}

VOID Instrument_AAA(INS ins, VOID *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_AL,
		 IARG_PTR, src,
		 IARG_END);

  //eflags <- src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_PTR, src,
		 IARG_END);

}

VOID Instrument_AAS(INS ins, VOID *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_AL,
		 IARG_PTR, src,
		 IARG_END);

  //eflags <- src
  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
		 IARG_PTR, src,
		 IARG_END);

}
*/

VOID Instrument_FLD(INS ins, VOID *v)
{
}

VOID Instrument_FST(INS ins, VOID *v)
{
}

VOID Instrument_FSTP(INS ins, VOID *v)
{
}

VOID Instrument_FXCH(INS ins, VOID *v)
{
}

VOID Instrument_ROL(INS ins, VOID *v)
{
    //TODO : check with Jim
}

VOID Instrument_ROR(INS ins, VOID *v)
{
    //TODO : check with Jim
}

VOID Instrument_FILD(INS ins, VOID *v)
{
}

VOID Instrument_FISTP(INS ins, VOID *v)
{
}

VOID EmptyHandler(INS ins, VOID *v)
{
}

VOID Instrument_FDIV(INS ins, VOID *v)
{
    //TODO : check with Jim
}

VOID Instrument_FADDP(INS ins, VOID *v)
{
    //TODO : check with Jim
}

VOID Instrument_FNSTSW(INS ins, VOID *v)
{
	//TPS

    if (INS_OperandIsReg(ins, 0)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintForRegister),
                IARG_ADDRINT, INS_OperandReg(ins, 0),
        		IARG_UINT32, INS_Opcode(ins),
                IARG_UINT32, 1,
                IARG_END);
    }
}

VOID Instrument_FUCOM(INS ins, VOID *v)
{
    //TODO
}

VOID Instrument_FDIVRP(INS ins, VOID *v)
{

}

//additions

//added to support strlen
VOID Instrument_PXOR(INS ins, VOID *v)
{

	//get taint for first operand
	if(INS_OperandIsReg(ins, 0)){
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_PTR, dest,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
	}
	else {
		log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	    log.flush();
	    abort();
	}


	  if(INS_OperandIsReg(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 1)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

    //TPS
    //dest <- dest U src
    if(INS_OperandIsReg(ins, 0)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
  		   IARG_ADDRINT, INS_OperandReg(ins, 0),
  		   IARG_UINT32, INS_Opcode(ins),
           IARG_UINT32, 1,
           IARG_UINT32, 2,
  		   IARG_PTR, dest,
  		   IARG_PTR, src,
  		   IARG_END);
    }
    else {
        log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
        log.flush();
        abort();
    }


}

//added to support strlen
VOID Instrument_PCMPEQB(INS ins, VOID *v)
{
	  if(INS_OperandIsReg(ins, 0)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  if(INS_OperandIsReg(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 1)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else if(INS_OperandIsImmediate(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  //TPS

	  //dest <- dest, src
	  if(INS_OperandIsReg(ins, 0)) {

		//taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 2,
			   IARG_PTR, dest,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryWrite(ins)) return;

	    //taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
			   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 2,
			   IARG_PTR, dest,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	    abort();
	  }
}

//added to support strlen
VOID Instrument_PMOVMSKB(INS ins, VOID *v)
{
	  if(INS_OperandIsReg(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 1)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else if(INS_OperandIsImmediate(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  //TPS

	  //dest <- src
	  if(INS_OperandIsReg(ins, 0)) {

		//taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 1,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryWrite(ins)) return;

	    //taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
			   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 1,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	    abort();
	  }
}

VOID Instrument_MOVHPD(INS ins, VOID *v)
{
  Instrument_MOV(ins, v);
}

VOID Instrument_MOVLPD(INS ins, VOID *v)
{
  Instrument_MOV(ins, v);
}
VOID Instrument_PSUBB(INS ins, VOID *v)
{
  Instrument_ADD(ins, v);
}

VOID Instrument_MOVDQA(INS ins, VOID *v)
{
  Instrument_MOV(ins, v);
}

VOID Instrument_MOVDQU(INS ins, VOID *v)
{
  Instrument_MOV(ins, v);
}

VOID Instrument_MOVAPS(INS ins, VOID *v)
{
  Instrument_MOV(ins, v);
}

VOID Instrument_PALIGNR(INS ins, VOID *v){
	  if(INS_OperandIsReg(ins, 0)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  if(INS_OperandIsReg(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 1)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else if(INS_OperandIsImmediate(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  //TPS

	  //dest <- dest, src
	  if(INS_OperandIsReg(ins, 0)) {

		//taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 2,
			   IARG_PTR, dest,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryWrite(ins)) return;

	    //taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
			   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 2,
			   IARG_PTR, dest,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	    abort();
	  }
}

VOID Instrument_MOVD(INS ins, VOID *v)
{
  Instrument_MOV(ins, v);
}

VOID Instrument_PSHUFD(INS ins, VOID *v){
	  if(INS_OperandIsReg(ins, 0)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  if(INS_OperandIsReg(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 1)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else if(INS_OperandIsImmediate(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  //TPS

	  //dest <- dest, src
	  if(INS_OperandIsReg(ins, 0)) {

		//taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 2,
			   IARG_PTR, dest,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryWrite(ins)) return;

	    //taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
			   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 2,
			   IARG_PTR, dest,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	    abort();
	  }
}

VOID Instrument_MOVQ(INS ins, VOID *v)
{
  Instrument_MOV(ins, v);
}

VOID Instrument_PREFETCHT0(INS ins, VOID *v)
{

}

VOID Instrument_CMPSW(INS ins, VOID *v)
{
  int operand_count = 0;
  for(unsigned int i = 0; i < INS_OperandCount(ins); i++) {
	  if(!INS_OperandIsImplicit(ins, i)) operand_count++;
  }

  if(operand_count==2){
	  Instrument_CMP(ins, v);
  }
  if(operand_count==1){
	  if(INS_OperandIsReg(ins, 0)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  //TPS

	  //eflags <- dest
	  INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
			 IARG_ADDRINT, LEVEL_BASE::REG_EFLAGS,
			 IARG_UINT32, INS_Opcode(ins),
			 IARG_UINT32, 1,
	         IARG_UINT32, 1,
			 IARG_PTR, dest,
			 IARG_END);
  }
}

VOID Instrument_XORPS(INS ins, VOID *v){
	  if(INS_OperandIsReg(ins, 0)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 0),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 0),
			   IARG_PTR, dest,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  if(INS_OperandIsReg(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 1)) {
	    if(!INS_IsMemoryRead(ins)) return;

	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForMemory),
			   IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE,
			   IARG_ADDRINT, INS_OperandMemoryBaseReg(ins, 1),
			   IARG_ADDRINT, INS_OperandMemoryIndexReg(ins, 1),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
			   IARG_END);
	  }
	  else if(INS_OperandIsImmediate(ins, 1)) {
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(ClearTaintSet),
			   IARG_PTR, src,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	      abort();
	  }

	  //TPS

	  //dest <- dest, src
	  if(INS_OperandIsReg(ins, 0)) {

		//taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
			   IARG_ADDRINT, INS_OperandReg(ins, 0),
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 2,
			   IARG_PTR, dest,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else if(INS_OperandIsMemory(ins, 0)) {
	    if(!INS_IsMemoryWrite(ins)) return;

	    //taint propagation
	    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForMemory),
			   IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE,
			   IARG_UINT32, INS_Opcode(ins),
			   IARG_UINT32, 1,
	           IARG_UINT32, 2,
			   IARG_PTR, dest,
			   IARG_PTR, src,
			   IARG_END);
	  }
	  else {
	      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
	      log.flush();
	    abort();
	  }
}

VOID Instrument_Sysenter(INS ins, VOID *v)
{
}

VOID Instrument_XGETBV(INS ins, VOID *v)
{
  if(INS_OperandIsReg(ins, 1)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 1),
		   IARG_PTR, src,
		   IARG_UINT32, INS_Opcode(ins),
		   IARG_END);
  }
  else {
      log << "Unknown operand(1) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }

  //TPS

  //dest <- src
  if(INS_OperandIsReg(ins, 0)) {
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetTaintForRegister),
		   IARG_ADDRINT, INS_OperandReg(ins, 0),
		   IARG_UINT32, INS_Opcode(ins),
           	   IARG_UINT32, 1,
           	   IARG_UINT32, 1,
		   IARG_PTR, src,
		   IARG_END);
  }
  else {
      log << "Unknown operand(0) type: " << INS_Disassemble(ins) << "\n";
      log.flush();
      abort();
  }
}
