#ifndef _INSTRUMENT_FUNCTIONS_H
#define _INSTRUMENT_FUNCTIONS_H

#include "pin.H"

#include <fstream>
#include <iostream>

#include "globals.h"
#include "taint_handling.h"

//function declarations
VOID UnimplementedInstruction(INS ins, VOID *v);
ADDRINT CheckCMOVNB(ADDRINT eflags);
ADDRINT CheckCMOVB(ADDRINT eflags);
ADDRINT CheckCMOVBE(ADDRINT eflags);
ADDRINT CheckCMOVNLE(ADDRINT eflags);
ADDRINT CheckCMOVNL(ADDRINT eflags);
ADDRINT CheckCMOVL(ADDRINT eflags);
ADDRINT CheckCMOVLE(ADDRINT eflags);
ADDRINT CheckCMOVNBE(ADDRINT eflags);
ADDRINT CheckCMOVNZ(ADDRINT eflags);
ADDRINT CheckCMOVNO(ADDRINT eflags);
ADDRINT CheckCMOVNP(ADDRINT eflags);
ADDRINT CheckCMOVNS(ADDRINT eflags);
ADDRINT CheckCMOVO(ADDRINT eflags);
ADDRINT CheckCMOVP(ADDRINT eflags);
ADDRINT CheckCMOVS(ADDRINT eflags);
ADDRINT CheckCMOVZ(ADDRINT eflags);
ADDRINT CheckEqual_r_r(ADDRINT v1, ADDRINT v2);
ADDRINT CheckNotEqual_r_r(ADDRINT v1, ADDRINT v2);
ADDRINT CheckEqual_m_r(ADDRINT start, ADDRINT size, ADDRINT v2);
ADDRINT CheckNotEqual_m_r(ADDRINT start, ADDRINT size, ADDRINT v2);
VOID Instrument_ADC(INS ins, VOID *v);
VOID Instrument_ADD(INS ins, VOID *v);
VOID Instrument_AND(INS ins, VOID *v);
VOID Instrument_BSWAP(INS ins, VOID *v);
VOID Instrument_CALL_NEAR(INS ins, VOID *v);
VOID Instrument_CDQ(INS ins, VOID *v);
VOID Instrument_CLD(INS ins, VOID *v);
VOID Instrument_CMOVcc(INS ins, VOID *v);
VOID Instrument_CMP(INS ins, VOID *v);
VOID Instrument_CMPSB(INS ins, VOID *v);
VOID Instrument_CMPXCHG(INS ins, VOID *v);
VOID Instrument_CWDE(INS ins, VOID *v);
VOID Instrument_DEC(INS ins, VOID *v);
VOID Instrument_DIV(INS ins, VOID *v);
VOID Instrument_FLDCW(INS ins, VOID *v);
VOID Instrument_FLDZ(INS ins, VOID *v);
VOID Instrument_FNSTCW(INS ins, VOID *v);
VOID Instrument_CPUID(INS ins, VOID *v);
VOID Instrument_BSF(INS ins, VOID *v);
VOID Instrument_BSR(INS ins, VOID *v);
VOID Instrument_BT(INS ins, VOID *v);
VOID Instrument_HLT(INS ins, VOID *v);
VOID Instrument_IDIV(INS ins, VOID *v);
VOID Instrument_MUL(INS ins, VOID *v);
VOID Instrument_IMUL(INS ins, VOID *v);
VOID Instrument_INC(INS ins, VOID *v);
VOID Instrument_INT(INS ins, VOID *v);
VOID Instrument_Jcc(INS ins, VOID *v);
VOID Instrument_JMP(INS ins, VOID *v);
VOID Instrument_LEA(INS ins, VOID *v);
VOID Instrument_LEAVE(INS ins, VOID *v);
VOID Instrument_LDMXCSR(INS ins, VOID *v);
VOID Instrument_MOV(INS ins, VOID *v);
VOID Instrument_MOVS(INS ins, VOID *v);
VOID Instrument_MOVSB(INS ins, VOID *v);
VOID Instrument_MOVSD(INS ins, VOID *v);
VOID Instrument_MOVSD_XMM(INS ins, VOID *v);
VOID Instrument_MOVSW(INS ins, VOID *v);
VOID Instrument_MOVSX(INS ins, VOID *v);
VOID Instrument_MOVZX(INS ins, VOID *v);
VOID Instrument_NEG(INS ins, VOID *v);
VOID Instrument_NOT(INS ins, VOID *v);
VOID Instrument_OR(INS ins, VOID *v);
VOID Instrument_PAUSE(INS ins, VOID *v);
VOID Instrument_NOP(INS ins, VOID *v);
VOID Instrument_POP(INS ins, VOID *v);
VOID Instrument_POPFD(INS ins, VOID *v);
VOID Instrument_PUSH(INS ins, VOID *v);
VOID Instrument_PUSHFD(INS ins, VOID *v);
VOID Instrument_Eflags(INS ins, VOID *v);
VOID Instrument_SAHF(INS ins, VOID *v);
VOID Instrument_LAHF(INS ins, VOID *v);
VOID Instrument_RDTSC(INS ins, VOID *v);
VOID Instrument_RET_NEAR(INS ins, VOID *v);
VOID Instrument_SAR(INS ins, VOID *v);
VOID Instrument_SBB(INS ins, VOID *v);
VOID Instrument_SCASB(INS ins, VOID *v);
VOID Instrument_SETcc(INS ins, VOID *v);
VOID Instrument_SHL(INS ins, VOID *v);
VOID Instrument_SHLD(INS ins, VOID *v);
VOID Instrument_SHR(INS ins, VOID *v);
VOID Instrument_SHRD(INS ins, VOID *v);
VOID Instrument_STD(INS ins, VOID *v);
VOID Instrument_STMXCSR(INS ins, VOID *v);
VOID Instrument_STOSB(INS ins, VOID *v);
VOID Instrument_STOSD(INS ins, VOID *v);
VOID Instrument_SUB(INS ins, VOID *v);
VOID Instrument_TEST(INS ins, VOID *v);
VOID Instrument_XADD(INS ins, VOID *v);
VOID Instrument_XCHG(INS ins, VOID *v);
VOID Instrument_XOR(INS ins, VOID *v);
VOID Instrument_FLD(INS ins, VOID *v);
VOID Instrument_FST(INS ins, VOID *v);
VOID Instrument_FSTP(INS ins, VOID *v);
VOID Instrument_FXCH(INS ins, VOID *v);
VOID Instrument_ROL(INS ins, VOID *v);
VOID Instrument_ROR(INS ins, VOID *v);
VOID Instrument_FILD(INS ins, VOID *v);
VOID Instrument_FISTP(INS ins, VOID *v);
VOID EmptyHandler(INS ins, VOID *v);
VOID Instrument_FDIV(INS ins, VOID *v);
VOID Instrument_FADDP(INS ins, VOID *v);
VOID Instrument_FNSTSW(INS ins, VOID *v);
VOID Instrument_FUCOM(INS ins, VOID *v);
VOID Instrument_FDIVRP(INS ins, VOID *v);
VOID Instrument_PXOR(INS ins, VOID *v);
VOID Instrument_PCMPEQB(INS ins, VOID *v);
VOID Instrument_PMOVMSKB(INS ins, VOID *v);
VOID Instrument_MOVHPD(INS ins, VOID *v);
VOID Instrument_MOVLPD(INS ins, VOID *v);
VOID Instrument_PSUBB(INS ins, VOID *v);
VOID Instrument_MOVDQA(INS ins, VOID *v);
VOID Instrument_MOVDQU(INS ins, VOID *v);
VOID Instrument_MOVAPS(INS ins, VOID *v);
VOID Instrument_PALIGNR(INS ins, VOID *v);
VOID Instrument_MOVD(INS ins, VOID *v);
VOID Instrument_PSHUFD(INS ins, VOID *v);
VOID Instrument_MOVQ(INS ins, VOID *v);
VOID Instrument_PREFETCHT0(INS ins, VOID *v);
VOID Instrument_CMPSW(INS ins, VOID *v);
VOID Instrument_XORPS(INS ins, VOID *v);
VOID Instrument_Sysenter(INS ins, VOID *v);
VOID Instrument_XGETBV(INS ins, VOID *v);

#endif
