#include "dytan.h"

//variables
map<ADDRINT, bitset *> memTaintMap;
map<REG, bitset *> regTaintMap;
map<ADDRINT, bitset *> controlTaintMap;
map<string, int> profilingMap;

bitset *dest;
bitset *src;
bitset *eax;
bitset *edx;
bitset *base;
bitset *idx;
bitset *eflags;
bitset *cnt;

bool tracing;
bool profiling_marks;
bool profiling_markop;
bool word;
int word_size;

bool controlFlowTainting;

int NUMBER_OF_TAINT_MARKS = 4096;
TaintGenerator *taintGen;


InstrumentFunction instrument_functions[XED_ICLASS_LAST];
PathTaintSource *path_source;
NetworkTaintSource *network_source;
FunctionTaintSource *func_source;

std::ofstream log;
std::ofstream prof_log;
std::ostringstream prof_stream;

//setting framework options
int set_framework_options(config *conf, SyscallMonitor *monitor)
{

	//initialization
	if(conf->sources.size()==0){
		//basic set up
		path_source = new PathTaintSource(monitor, false);
		network_source = new NetworkTaintSource(monitor, false);
		func_source = new FunctionTaintSource();
        if (!conf->num_markings.compare("1")) {
            taintGen = new ConstantTaintGenerator(5);
        } else if (conf->num_markings.compare("")) {
            int num = convertTo<int>(conf->num_markings);
            if (num < 1 || num > NUMBER_OF_TAINT_MARKS) {
                cout << "Incorrect number of taint marks specified";
                exit(1);
            }
            NUMBER_OF_TAINT_MARKS = num;
            taintGen = new TaintGenerator(0, num);
        }
	}

	//case in which I have moultiple sources
    vector<source>::iterator itr = conf->sources.begin();
    // Iterate through all the taint sources
    while (itr != conf->sources.end()) {
        source src = *itr;
        itr++;
        // Specifies whether to taint per byte or per read for IO sources
        taint_range_t taint_granularity = PerRead;
        if (!src.granularity.compare("PerRead")) {
            taint_granularity = PerRead;
        } else if (!src.granularity.compare("PerByte")) {
            taint_granularity = PerByte;
        }


        if (!conf->num_markings.compare("1")) {
            taintGen = new ConstantTaintGenerator(5);
        } else if (conf->num_markings.compare("")) {
            int num = convertTo<int>(conf->num_markings);
            if (num < 1 || num > NUMBER_OF_TAINT_MARKS) {
                cout << "Incorrect number of taint marks specified";
                exit(1);
            }
            NUMBER_OF_TAINT_MARKS = num;
            taintGen = new TaintGenerator(0, num);
        }


        if (!src.type.compare("path")) {
            if(!src.details[0].compare("*")) {
                path_source = new PathTaintSource(monitor, true);
                path_source->addObserverForAll(taint_granularity);
            }else {
                path_source = new PathTaintSource(monitor, false);
                for (unsigned int i = 0; i < src.details.size(); i++) {
                    string actual_path = src.details[i];
                    path_source->addPathSource(actual_path, taint_granularity);
                }
            }
        } else if (!src.type.compare("network")) {
            if(!src.details[0].compare("*")) {
                network_source = new NetworkTaintSource(monitor, true);
                network_source->addObserverForAll(taint_granularity);
            }else {
                network_source = new NetworkTaintSource(monitor, false);
                // add network source
                for (unsigned int i = 0; i < src.details.size(); i+=2) {
                    string host_ip = src.details[i];
                    string host_port = src.details[i+1];
                    network_source->addNetworkSource(host_ip, host_port, taint_granularity);
                }
            }
        } else if (!src.type.compare("function")) {
            func_source = new FunctionTaintSource();
	    //TODO: remove hard coding
            //return value of function is tainted
            //func_source->addFunctionSource("funcname", num_taint_marks);
        } else {
            std::cout << "Invalid source type";
        }
    }

    return 0;
}

void PushControl(ADDRINT addr)
{
#ifdef TRACE
  if(tracing) {
      log << "\tpush control: " << std::hex << addr << "\n";
      log.flush();
  }
#endif

  if(regTaintMap.end() == regTaintMap.find(LEVEL_BASE::REG_EFLAGS) ||
     bitset_is_empty(regTaintMap[LEVEL_BASE::REG_EFLAGS])) return;

    if(controlTaintMap.end() == controlTaintMap.find(addr)) {
        controlTaintMap[addr] = bitset_init(NUMBER_OF_TAINT_MARKS);
    }
    bitset_union(controlTaintMap[addr], regTaintMap[LEVEL_BASE::REG_EFLAGS]);


  //dump control taint map
#ifdef TRACE
  if(tracing) {
    for(map<ADDRINT, bitset *>::iterator iter = controlTaintMap.begin();
	iter != controlTaintMap.end(); iter++) {

       const char *sep = "";
        log << "\t\t-" << std::hex << iter->first << " - [";
      for(int i = 0; i < (int)iter->second->nbits; i++) {
	if(bitset_test_bit(iter->second, i)) {
        log << sep << i;
	  sep = ", ";
	}
      }
        log << "]\n";
        log.flush();
    }
  }
#endif
}

void PopControl(int n, ...)
{
#ifdef TRACE
  if(tracing) {
    log <<  "\tpop control: ";
    log.flush();
  }
#endif

  va_list ap;
  ADDRINT addr;
  const char *sep = "";

  va_start(ap, n);

  for (; n; n--) {

    addr = va_arg(ap, ADDRINT);

#ifdef TRACE
    if(tracing) {
        log << sep << std::hex << addr << "\n";
        log.flush();
      sep = ", ";
    }
#endif
    if(controlTaintMap.end() == controlTaintMap.find(addr)) return;

    bitset *s = controlTaintMap[addr];
    bitset_free(s);

    controlTaintMap.erase(addr);

  }
  va_end(ap);

#ifdef TRACE
  if(tracing) {
    log << "\n";
    log.flush();
  }
#endif

  // dump control taint map
#ifdef TRACE
  if(tracing) {
    for(map<ADDRINT, bitset *>::iterator iter = controlTaintMap.begin();
	iter != controlTaintMap.end(); iter++) {

      sep = "";
      log << "\t\t" << std::hex << iter->first << " - [";
      for(int i = 0; i < (int)iter->second->nbits; i++) {
      if(bitset_test_bit(iter->second, i)) {
          log << sep << i;
          sep = ", ";
      }
      }
      log << "]\n";
      log.flush();
    }
  }
#endif
}

//TODO check this function when controlflow is needed
static void Controlflow(RTN rtn, void *v)
{
  string rtn_name = RTN_Name(rtn);

  IMG img = SEC_Img(RTN_Sec(rtn));

  if(LEVEL_CORE::IMG_TYPE_SHAREDLIB == IMG_Type(img)) return;

  RTN_Open(rtn);

  RoutineGraph *rtnGraph = new RoutineGraph(rtn);

  map<ADDRINT, set<ADDRINT> > controls;

  for(INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {

    if(XED_CATEGORY_COND_BR == INS_Category(ins)) {

      ADDRINT addr = INS_Address(ins);
      BasicBlock *block = rtnGraph->addressMap[addr];
      if(NULL == block) {
	//printf("block is null\n");
	//fflush(stdout);
	continue;
      }

      BasicBlock *ipdomBlock = block->getPostDominator();
      if(NULL == ipdomBlock) {
	//printf("ipdomBlock is null in %s\n", rtn_name.c_str());
	//fflush(stdout);
	continue;
      }
      ADDRINT ipdomAddr = ipdomBlock->startingAddress;

      if(controls.find(ipdomAddr) == controls.end()) {
	controls[ipdomAddr] = set<ADDRINT>();
      }

      controls[ipdomAddr].insert(addr);

      //      printf("placing push call: %#x - %s\n", addr,
      //     INS_Disassemble(ins).c_str());

      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(PushControl),
		     IARG_PTR, addr,
		     IARG_END);
    }
  }

  for(INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {

    ADDRINT addr = INS_Address(ins);

    if(controls.end() == controls.find(addr)) continue;

    IARGLIST args = IARGLIST_Alloc();

    for(set<ADDRINT>::iterator iter = controls[addr].begin();
	iter != controls[addr].end(); iter++) {
      IARGLIST_AddArguments(args, IARG_ADDRINT, *iter, IARG_END);
      //      printf("\t%#x\n", *iter);
    }


    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(PopControl),
		   IARG_UINT32, controls[addr].size(),
		   IARG_IARGLIST, args,
		   IARG_END);
    IARGLIST_Free(args);
  }

  delete rtnGraph;

  RTN_Close(rtn);
}

//instrumenting each instruction for dataflow propagation
static void Dataflow(INS ins, void *v)
{
    xed_iclass_enum_t opcode = (xed_iclass_enum_t) INS_Opcode(ins);

    (*instrument_functions[opcode])(ins, v);
}

VOID SysBefore(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *val)
{

    SyscallMonitor *monitor = static_cast<SyscallMonitor *>(val);
    monitor->beginSyscall(threadIndex, PIN_GetSyscallNumber(ctxt, std), PIN_GetSyscallArgument(ctxt, std, 0), PIN_GetSyscallArgument(ctxt, std, 1),
                          PIN_GetSyscallArgument(ctxt, std, 2), PIN_GetSyscallArgument(ctxt, std, 3), PIN_GetSyscallArgument(ctxt, std, 4), PIN_GetSyscallArgument(ctxt, std, 5));


}

VOID SysAfter(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *val)
{
    SyscallMonitor *monitor = static_cast<SyscallMonitor *>(val);

    monitor->endSyscall(threadIndex, PIN_GetSyscallReturn(ctxt, std), PIN_GetSyscallErrno(ctxt, std));
}

//dumps the instruction to the log file
void Print(ADDRINT address, string *disas)
{
  if(tracing) {
      log << std::hex << address << ": " << disas << " [" << RTN_FindNameByAddress(address) << "]\n";
      log.flush();
  }
}

static void Trace(INS ins, void *v)
{
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(Print),
            IARG_ADDRINT, INS_Address(ins),
            IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_END);
}



//function that stores to file profiling info
void PrintProfilingResult(INT32 code, void *v){
	int count=0;
	for(map<string, int>::iterator profiling_it = profilingMap.begin(); profiling_it != profilingMap.end(); profiling_it++) {
		//cout << profiling_it->second << "\t" << profiling_it->first << "\n";
		prof_log << profiling_it->second << "\t" << profiling_it->first << "\n";
		prof_log.flush();
		count++;
	}
	log << "Total number of keys:" << std::dec << count << "\n";
}

int main(int argc, char *argv[])
{
	//creating configuration structure to store configuration info
	config *conf = new config;

	//create output log
	log.open("out.log");

	//parsing xml configuration file
	if(parseConfig(argc, argv, conf)==-1){
		//error configuration file
		exit(-1);
	}

	//initialize PIN
    PIN_InitSymbols();
    PIN_Init(argc, argv);

    //create syscall monitor
    SyscallMonitor *monitor = new SyscallMonitor();

    //setting framework options
    set_framework_options(conf, monitor);

    //initializing taint mark holders
    dest = bitset_init(NUMBER_OF_TAINT_MARKS);
    src = bitset_init(NUMBER_OF_TAINT_MARKS);
    eax = bitset_init(NUMBER_OF_TAINT_MARKS);
    edx = bitset_init(NUMBER_OF_TAINT_MARKS);
    base = bitset_init(NUMBER_OF_TAINT_MARKS);
    idx = bitset_init(NUMBER_OF_TAINT_MARKS);
    eflags = bitset_init(NUMBER_OF_TAINT_MARKS);
    cnt = bitset_init(NUMBER_OF_TAINT_MARKS);

    //profiling info
    tracing = false;
    profiling_marks = conf->prof.marks;
    profiling_markop = conf->prof.markop;
    if(profiling_marks){
        prof_log.open("prof.log");
    }
    if(profiling_markop){
    	prof_log.open("prof.log");
    	PIN_AddFiniFunction(PrintProfilingResult,0);
    	word = true;
    	word_size=4;
    }

//    //set up taint sinks
//    vector<sink>::iterator itr2 = conf->sinks.begin();
//    while (itr2 != conf->sinks.end()) {
//        sink snk = *itr2;
//        itr2++;
//        //TODO
//    }

    IMG_AddInstrumentFunction(ReplaceUserFunctions, 0);

    //this is how to mark inputs to the program
    RTN_AddInstrumentFunction(taint_routines, 0);

	#ifdef TRACE
    	INS_AddInstrumentFunction(Trace, 0);
	#endif

    //set up type of taint propagation
    if(conf->prop.dataflow){
    	//instrument at instruction granularity
    	INS_AddInstrumentFunction(Dataflow, 0);
    }
    if(conf->prop.controlflow){
    	//instrument at routing granularity
    	RTN_AddInstrumentFunction(Controlflow, 0);
    	controlFlowTainting = true;
    }
    else{
    	controlFlowTainting = false;
    }

    /*	This the large dispatch table that associated a dataflow instrumentation
    	function with an instruction opcode. See instrument_functions.cpp for
       	the actually instrumentation functions. There is also default handling function
    	that aborts.  This makes sure I don't miss instructions in new applications
    */

    for(int i = 0; i < XED_ICLASS_LAST; i++) {
        instrument_functions[i] = &UnimplementedInstruction;
    }

    instrument_functions[XED_ICLASS_ADD] = &Instrument_ADD;
    instrument_functions[XED_ICLASS_PUSH] = &Instrument_PUSH;
    instrument_functions[XED_ICLASS_POP] = &Instrument_POP;
    instrument_functions[XED_ICLASS_OR] = &Instrument_OR;
    instrument_functions[XED_ICLASS_ADC] = &Instrument_ADC;
    instrument_functions[XED_ICLASS_SBB] = &Instrument_SBB;
    instrument_functions[XED_ICLASS_AND] = &Instrument_AND;
//  instrument_functions[XED_ICLASS_DAA] = &Instrument_DAA;
    instrument_functions[XED_ICLASS_SUB] = &Instrument_SUB;
//  instrument_functions[XED_ICLASS_DAS] = &Instrument_DAS;
    instrument_functions[XED_ICLASS_XOR] = &Instrument_XOR;
//  instrument_functions[XED_ICLASS_AAA] = &Instrument_AAA;
    instrument_functions[XED_ICLASS_CMP] = &Instrument_CMP;
//	instrument_functions[XED_ICLASS_AAS] = &Instrument_AAS;
    instrument_functions[XED_ICLASS_INC] = &Instrument_INC;
    instrument_functions[XED_ICLASS_DEC] = &Instrument_DEC;
//	instrument_functions[XED_ICLASS_PUSHAD] = &Instrument_PUSHAD;
//	instrument_functions[XED_ICLASS_POPAD] = &Instrument_POPAD;
//	instrument_functions[XED_ICLASS_BOUND] = &Instrument_BOUND;
//	instrument_functions[XED_ICLASS_ARPL] = &Instrument_ARPL;
    instrument_functions[XED_ICLASS_IMUL] = &Instrument_IMUL;
//	instrument_functions[XED_ICLASS_INSB] = &Instrument_INSB;
//	instrument_functions[XED_ICLASS_INSD] = &Instrument_INSD;
//	instrument_functions[XED_ICLASS_OUTSB] = &Instrument_OUTSB;
//	instrument_functions[XED_ICLASS_OUTSD] = &Instrument_OUTSD;
    instrument_functions[XED_ICLASS_JO] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JNO] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JB] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JNB] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JZ] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JNZ] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JBE] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JNBE] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JS] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JNS] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JP] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JNP] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JL] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JNL] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JLE] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_JNLE] = &Instrument_Jcc;
    instrument_functions[XED_ICLASS_CMOVNLE] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_TEST] = &Instrument_TEST;
    instrument_functions[XED_ICLASS_XCHG] = &Instrument_XCHG;
    instrument_functions[XED_ICLASS_MOV] = &Instrument_MOV;
    instrument_functions[XED_ICLASS_XGETBV] = &Instrument_XGETBV;
    instrument_functions[XED_ICLASS_LEA] = &Instrument_LEA;
    instrument_functions[XED_ICLASS_PAUSE] = &Instrument_PAUSE;
    instrument_functions[XED_ICLASS_CWDE] = &Instrument_CWDE;
    instrument_functions[XED_ICLASS_CDQ] = &Instrument_CDQ;
//	instrument_functions[XED_ICLASS_CALL_FAR] = &Instrument_CALL_FAR;
//	instrument_functions[XED_ICLASS_WAIT] = &Instrument_WAIT;
    instrument_functions[XED_ICLASS_CMPSW] = &Instrument_CMPSW;
    instrument_functions[XED_ICLASS_PUSHFD] = &Instrument_PUSHFD;
    instrument_functions[XED_ICLASS_POPFD] = &Instrument_POPFD;
    instrument_functions[XED_ICLASS_SAHF] = &Instrument_SAHF;
    instrument_functions[XED_ICLASS_LAHF] = &Instrument_LAHF;
    instrument_functions[XED_ICLASS_MOVSB] = &Instrument_MOVSB;
    instrument_functions[XED_ICLASS_MOVSW] = &Instrument_MOVSW;
    instrument_functions[XED_ICLASS_CMPSB] = &Instrument_CMPSB;
//	instrument_functions[XED_ICLASS_CMPSD] = &Instrument_CMPSD;
    instrument_functions[XED_ICLASS_STOSB] = &Instrument_STOSB;
//	instrument_functions[XED_ICLASS_STOSW] = &Instrument_STOSW;
    instrument_functions[XED_ICLASS_STOSD] = &Instrument_STOSD;
//	instrument_functions[XED_ICLASS_LODSB] = &Instrument_LODSB;
//	instrument_functions[XED_ICLASS_LODSD] = &Instrument_LODSD;
    instrument_functions[XED_ICLASS_SCASB] = &Instrument_SCASB;
//	instrument_functions[XED_ICLASS_SCASD] = &Instrument_SCASD;
    instrument_functions[XED_ICLASS_RET_NEAR] = &Instrument_RET_NEAR;
//	instrument_functions[XED_ICLASS_LES] = &Instrument_LES;
//	instrument_functions[XED_ICLASS_LDS] = &Instrument_LDS;
//	instrument_functions[XED_ICLASS_ENTER] = &Instrument_ENTER;
    instrument_functions[XED_ICLASS_LEAVE] = &Instrument_LEAVE;
//	instrument_functions[XED_ICLASS_RET_FAR] = &Instrument_RET_FAR;
//	instrument_functions[XED_ICLASS_INT3] = &Instrument_INT3;
    instrument_functions[XED_ICLASS_INT] = &Instrument_INT;
//	instrument_functions[XED_ICLASS_INT0] = &Instrument_INT0;
//	instrument_functions[XED_ICLASS_IRETD] = &Instrument_IRETD;
//	instrument_functions[XED_ICLASS_AAM] = &Instrument_AAM;
//	instrument_functions[XED_ICLASS_AAD] = &Instrument_AAD;
//	instrument_functions[XED_ICLASS_SALC] = &Instrument_SALC;
//	instrument_functions[XED_ICLASS_XLAT] = &Instrument_XLAT;
//	instrument_functions[XED_ICLASS_LOOPNE] = &Instrument_LOOPNE;
//	instrument_functions[XED_ICLASS_LOOPE] = &Instrument_LOOPE;
//	instrument_functions[XED_ICLASS_LOOP] = &Instrument_LOOP;
    instrument_functions[XED_ICLASS_JRCXZ] = &Instrument_Jcc;
//	instrument_functions[XED_ICLASS_IN] = &Instrument_IN;
//	instrument_functions[XED_ICLASS_OUT] = &Instrument_OUT;
    instrument_functions[XED_ICLASS_CALL_NEAR] = &Instrument_CALL_NEAR;
    instrument_functions[XED_ICLASS_JMP] = &Instrument_JMP;
//	instrument_functions[XED_ICLASS_JMP_FAR] = &Instrument_JMP_FAR;
//	instrument_functions[XED_ICLASS_INT_l] = &Instrument_INT_l;
    instrument_functions[XED_ICLASS_HLT] = &Instrument_HLT;
//	instrument_functions[XED_ICLASS_CMC] = &Instrument_CMC;
//	instrument_functions[XED_ICLASS_CLC] = &Instrument_CLC;
//	instrument_functions[XED_ICLASS_STC] = &Instrument_STC;
//	instrument_functions[XED_ICLASS_CLI] = &Instrument_CLI;
//	instrument_functions[XED_ICLASS_STI] = &Instrument_STI;
    instrument_functions[XED_ICLASS_CLD] = &Instrument_CLD;
    instrument_functions[XED_ICLASS_STD] = &Instrument_STD;
    instrument_functions[XED_ICLASS_RDTSC] = &Instrument_RDTSC;
    instrument_functions[XED_ICLASS_CMOVB] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_CMOVNB] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_CMOVZ] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_CMOVNZ] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_CMOVBE] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_CMOVNBE] = &Instrument_CMOVcc;
//	instrument_functions[XED_ICLASS_EMMS] = &Instrument_EMMS;
    instrument_functions[XED_ICLASS_SETB] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_SETNB] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_SETZ] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_SETNZ] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_SETBE] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_SETNBE] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_CPUID] = &Instrument_CPUID;
    instrument_functions[XED_ICLASS_BT] = &Instrument_BT;
    instrument_functions[XED_ICLASS_SHLD] = &Instrument_SHLD;
    instrument_functions[XED_ICLASS_CMPXCHG] = &Instrument_CMPXCHG;
//	instrument_functions[XED_ICLASS_BTR] = &Instrument_BTR;
    instrument_functions[XED_ICLASS_NOP] = &Instrument_NOP;
    instrument_functions[XED_ICLASS_NOP2] = &Instrument_NOP;
    instrument_functions[XED_ICLASS_NOP3] = &Instrument_NOP;
    instrument_functions[XED_ICLASS_NOP4] = &Instrument_NOP;
    instrument_functions[XED_ICLASS_NOP5] = &Instrument_NOP;
    instrument_functions[XED_ICLASS_NOP6] = &Instrument_NOP;
    instrument_functions[XED_ICLASS_NOP7] = &Instrument_NOP;
    instrument_functions[XED_ICLASS_NOP8] = &Instrument_NOP;
    instrument_functions[XED_ICLASS_NOP9] = &Instrument_NOP;
    instrument_functions[XED_ICLASS_MOVZX] = &Instrument_MOVZX;
    instrument_functions[XED_ICLASS_XADD] = &Instrument_XADD;
//	instrument_functions[XED_ICLASS_PSRLQ] = &Instrument_PSRLQ;
//	instrument_functions[XED_ICLASS_PADDQ] = &Instrument_PADDQ;
//	instrument_functions[XED_ICLASS_MOVQ] = &Instrument_MOVQ;
//	instrument_functions[XED_ICLASS_MOVQ2Q] = &Instrument_MOVDQ2Q;
//	instrument_functions[XED_ICLASS_PSLLQ] = &Instrument_PSLLQ;
//	instrument_functions[XED_ICLASS_PMULUDQ] = &Instrument_PMULUDQ;
//	instrument_functions[XED_ICLASS_UD2] = &Instrument_UD2;
    instrument_functions[XED_ICLASS_MOVAPS] = &Instrument_MOVAPS;
    instrument_functions[XED_ICLASS_MOVD] = &Instrument_MOVD;
    instrument_functions[XED_ICLASS_MOVDQA] = &Instrument_MOVDQA;
    instrument_functions[XED_ICLASS_MOVDQU] = &Instrument_MOVDQU;
    instrument_functions[XED_ICLASS_CMOVS] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_CMOVNS] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_MOVHPD] = &Instrument_MOVHPD;
    instrument_functions[XED_ICLASS_CMOVL] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_CMOVNL] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_CMOVLE] = &Instrument_CMOVcc;
    instrument_functions[XED_ICLASS_MOVLPD] = &Instrument_MOVLPD;
    instrument_functions[XED_ICLASS_MOVQ] = &Instrument_MOVQ;
    instrument_functions[XED_ICLASS_MOVSD] = &Instrument_MOVSD;
    instrument_functions[XED_ICLASS_MOVSD_XMM] = &Instrument_MOVSD_XMM;
    instrument_functions[XED_ICLASS_MUL] = &Instrument_MUL;
//	instrument_functions[XED_ICLASS_MOVD] = &Instrument_MOVD;
//	instrument_functions[XED_ICLASS_MOVDQU] = &Instrument_MOVDQU;
//	instrument_functions[XED_ICLASS_MOVDQA] = &Instrument_MOVDQA;
    instrument_functions[XED_ICLASS_SETS] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_SETL] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_SETNL] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_SETLE] = &Instrument_SETcc;
    instrument_functions[XED_ICLASS_SETNLE] = &Instrument_SETcc;
//	instrument_functions[XED_ICLASS_BTS] = &Instrument_BTS;
    instrument_functions[XED_ICLASS_SHRD] = &Instrument_SHRD;
    instrument_functions[XED_ICLASS_BSF] = &Instrument_BSF;
    instrument_functions[XED_ICLASS_BSR] = &Instrument_BSR;
    instrument_functions[XED_ICLASS_MOVSX] = &Instrument_MOVSX;
    instrument_functions[XED_ICLASS_BSWAP] = &Instrument_BSWAP;
    instrument_functions[XED_ICLASS_PALIGNR] = &Instrument_PALIGNR;
//	instrument_functions[XED_ICLASS_PAND] = &Instrument_PAND;
//	instrument_functions[XED_ICLASS_PSUBSW] = &Instrument_PSUBSW;
    instrument_functions[XED_ICLASS_PCMPEQB] = &Instrument_PCMPEQB;
    instrument_functions[XED_ICLASS_PMOVMSKB] = &Instrument_PMOVMSKB;
    instrument_functions[XED_ICLASS_ROL] = &Instrument_ROL;
    instrument_functions[XED_ICLASS_ROR] = &Instrument_ROR;
//	instrument_functions[XED_ICLASS_RCL] = &Instrument_RCL;
//	instrument_functions[XED_ICLASS_RCR] = &Instrument_RCR;
    instrument_functions[XED_ICLASS_SHL] = &Instrument_SHL;
    instrument_functions[XED_ICLASS_SHR] = &Instrument_SHR;
    instrument_functions[XED_ICLASS_SAR] = &Instrument_SAR;
    instrument_functions[XED_ICLASS_NOT] = &Instrument_NOT;
    instrument_functions[XED_ICLASS_NEG] = &Instrument_NEG;
//	instrument_functions[XED_ICLASS_POR] = &Instrument_POR;
    instrument_functions[XED_ICLASS_DIV] = &Instrument_DIV;
    instrument_functions[XED_ICLASS_PREFETCHT0] = &Instrument_PREFETCHT0;
    instrument_functions[XED_ICLASS_IDIV] = &Instrument_IDIV;
    instrument_functions[XED_ICLASS_PSHUFD] = &Instrument_PSHUFD;
    instrument_functions[XED_ICLASS_LDMXCSR] = &Instrument_LDMXCSR;
    instrument_functions[XED_ICLASS_STMXCSR] = &Instrument_STMXCSR;
    instrument_functions[XED_ICLASS_PSUBB] = &Instrument_PSUBB;
    instrument_functions[XED_ICLASS_FDIV] = &Instrument_FDIV;
    instrument_functions[XED_ICLASS_FLD] = &Instrument_FLD;
    instrument_functions[XED_ICLASS_FST] = &Instrument_FST;
    instrument_functions[XED_ICLASS_FSTP] = &Instrument_FSTP;
    instrument_functions[XED_ICLASS_FLDCW] = &Instrument_FLDCW;
    instrument_functions[XED_ICLASS_FNSTCW] = &Instrument_FNSTCW;
    instrument_functions[XED_ICLASS_FXCH] = &Instrument_FXCH;
    instrument_functions[XED_ICLASS_PXOR] = &Instrument_PXOR;
    instrument_functions[XED_ICLASS_FLDZ] = &Instrument_FLDZ;
    instrument_functions[XED_ICLASS_FILD] = &Instrument_FILD;
    instrument_functions[XED_ICLASS_FISTP] = &Instrument_FISTP;
    instrument_functions[XED_ICLASS_FNSTSW] = &Instrument_FNSTSW;
    instrument_functions[XED_ICLASS_FUCOM] = &Instrument_FUCOM;
    instrument_functions[XED_ICLASS_FADDP] = &Instrument_FADDP;
    instrument_functions[XED_ICLASS_FDIVRP] = &Instrument_FDIVRP;
    instrument_functions[XED_ICLASS_FDIVP] = &EmptyHandler;
    instrument_functions[XED_ICLASS_FIDIVR] = &EmptyHandler;
    instrument_functions[XED_ICLASS_FIADD] = &EmptyHandler;
    instrument_functions[XED_ICLASS_FIST] = &EmptyHandler;
    instrument_functions[XED_ICLASS_XORPS] = &Instrument_XORPS;
    instrument_functions[XED_ICLASS_FCOMI] = &Instrument_Eflags;
    instrument_functions[XED_ICLASS_FCOMIP] = &Instrument_Eflags;
    instrument_functions[XED_ICLASS_FUCOMI] = &Instrument_Eflags;
    instrument_functions[XED_ICLASS_FUCOMIP] = &Instrument_Eflags;
    instrument_functions[XED_ICLASS_SYSENTER] = &Instrument_Sysenter;

    //add instrumentation functions for syscall handling
    PIN_AddSyscallEntryFunction(SysBefore, (VOID *)monitor);
    PIN_AddSyscallExitFunction(SysAfter, (VOID *)monitor);

    /*	set a default observer that aborts when a program uses a system
    	call that we don't provide a handling function for.
    */
    monitor->setDefaultObserver(UnimplementedSystemCall);
    monitor->addObserver(SYS_access, Handle_ACCESS, 0);
    monitor->addObserver(SYS_alarm, Handle_ALARM, 0);
    monitor->addObserver(SYS_brk, Handle_BRK, 0);
    monitor->addObserver(SYS_chmod, Handle_CHMOD, 0);
    monitor->addObserver(SYS_close, Handle_CLOSE, 0);
    monitor->addObserver(SYS_dup, Handle_DUP, 0);
    monitor->addObserver(SYS_fcntl, Handle_FCNTL, 0);
    monitor->addObserver(SYS_flock, Handle_FLOCK, 0);
    monitor->addObserver(SYS_fstat, Handle_FSTAT, 0);
    monitor->addObserver(SYS_fstat64, Handle_FSTAT, 0);
    monitor->addObserver(SYS_fsync, Handle_FSYNC, 0);
    monitor->addObserver(SYS_ftruncate, Handle_FTRUNCATE, 0);
    monitor->addObserver(SYS_getdents64, Handle_GETDENTS64, 0);
    monitor->addObserver(SYS_getpid, Handle_GETPID, 0);
    monitor->addObserver(SYS_gettimeofday, Handle_GETTIMEOFDAY, 0);
    monitor->addObserver(SYS_getuid, Handle_GETUID, 0);
    monitor->addObserver(SYS_ioctl, Handle_IOCTL, 0);
    monitor->addObserver(SYS_link, Handle_LINK, 0);
    monitor->addObserver(SYS_lseek, Handle_LSEEK, 0);
    monitor->addObserver(SYS_lstat, Handle_LSTAT, 0);
    monitor->addObserver(SYS_mmap, Handle_MMAP, 0);
    monitor->addObserver(SYS_mmap2, Handle_MMAP2, 0);
    monitor->addObserver(SYS_mprotect, Handle_MPROTECT, 0);
    monitor->addObserver(SYS_munmap, Handle_MUNMAP, 0);
    monitor->addObserver(SYS_open, Handle_OPEN, 0);
    monitor->addObserver(SYS_read, Handle_READ, 0);
    monitor->addObserver(SYS_readlink, Handle_READLINK, 0);
    monitor->addObserver(SYS_rename, Handle_RENAME, 0);
    monitor->addObserver(SYS_rt_sigaction, Handle_RT_SIGACTION, 0);
    monitor->addObserver(SYS_rt_sigprocmask, Handle_RT_SIGPROCMASK, 0);
    monitor->addObserver(SYS_set_thread_area, Handle_SET_THREAD_AREA, 0);
    monitor->addObserver(SYS_stat, Handle_STAT, 0);
    monitor->addObserver(SYS_socketcall, Handle_SOCKET, 0);
    monitor->addObserver(SYS_time, Handle_TIME, 0);
    monitor->addObserver(SYS_uname, Handle_UNAME, 0);
    monitor->addObserver(SYS_unlink, Handle_UNLINK, 0);
    monitor->addObserver(SYS_utime, Handle_UTIME, 0);
    monitor->addObserver(SYS_write, Handle_WRITE, 0);
    monitor->addObserver(SYS_writev, Handle_WRITEV, 0);
    monitor->addObserver(SYS_poll, Handle_POLL, 0);
    monitor->addObserver(SYS_gettid, Handle_GETTID, 0);
    monitor->addObserver(SYS_tgkill, Handle_TGKILL, 0);
    monitor->addObserver(SYS_getgid, Handle_GETGID, 0);
    monitor->addObserver(SYS_geteuid, Handle_GETEUID, 0);
    monitor->addObserver(SYS_getegid, Handle_GETEGID, 0);
    monitor->addObserver(SYS_getdents, Handle_GETDENTS, 0);
    monitor->addObserver(SYS_clone, Handle_CLONE, 0);
    monitor->addObserver(SYS_dup2, Handle_DUP2, 0);
    monitor->addObserver(SYS_waitid, Handle_WAITID, 0);
    monitor->addObserver(SYS_set_tid_address, Handle_SET_TID_ADDRESS, 0);
    monitor->addObserver(SYS_chown, Handle_CHOWN, 0);

    //start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
