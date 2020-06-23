#include "taint_handling.h"

/*	 Dytan function for tainting memory range.
 	 @param addr - starting address of the memory to be tainted
 	 @param size - size of the memory range to be tainted
 	 @param taint_mark - OPTIONAL user supplied taint mark. -1 by default
 */
void SetNewTaintForMemory(ADDRINT addr, ADDRINT size, int taint_mark)
{
	printf("input %#x\n", (uint) addr);

    if (taint_mark == -1) {
        assert(taintGen);
        taint_mark = taintGen->nextTaintMark();
    } else if (taint_mark >= NUMBER_OF_TAINT_MARKS) {
        // check if the user assigned taint mark is legal
        fprintf(stderr, "Illegal taint mark: User supplied taint mark %d is "\
                "bigger than max taint mark (%d)", taint_mark, NUMBER_OF_TAINT_MARKS);
        abort();
    }

    bitset *tmp = bitset_init(NUMBER_OF_TAINT_MARKS);
    bitset_set_bit(tmp, taint_mark);

    for(ADDRINT address = (ADDRINT) addr;
            address < (ADDRINT) addr + size; address++) {
        memTaintMap[address] = bitset_copy(tmp);
    }

#ifdef TRACE
    //uncomment
//    const char *sep = "";
//    //log << "@" << std::hex << addr << "-" << std::hex <<  addr + size -1 << "[";
//    for(int i = 0; i < (int)tmp->nbits; i++) {
//        if(bitset_test_bit(tmp, i)) {
//            //log << sep << i;
//            sep = ", ";
//        }
//    }
    //log << "]\n";
    //log.flush();
#endif

    //taintAssignmentLog << taint_mark << " ->" << std::hex << addr << "-" << std::hex << addr + size - 1 << "\n";
    //taintAssignmentLog.flush();

    bitset_free(tmp);
}

void SetNewTaintStart(){
	int new_start = taintGen->getCurrent();
	taintGen->setStart(new_start);
}

//clear taint
void ClearTaintSet(bitset *set, unsigned int opcode)
{
  bitset_reset(set);
}

//copies the taint marks for the register into the out bitset parameter
void TaintForRegister(REG reg, bitset *set, unsigned int opcode)
{
  map<REG, bitset *>::iterator iter = regTaintMap.find(reg);
  if(regTaintMap.end() != iter) {
    bitset_set_bits(set, iter->second);
  }
  else {
    // this is important becuase we use global storage it's possible that
    // set will already have values
    bitset_reset(set);
  }

  if(profiling_markop){
	  prof_stream << bitset_str(set);
  }

#ifdef TRACE
  if(tracing) {
    const char *sep = "";
    if(REG_valid(reg)) {
       log << "\t-" << REG_StringShort(reg) << "[";
      for(int i = 0; i < (int)set->nbits; i++) {
	if(bitset_test_bit(set, i)) {
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

/* Return in the out parameter, set, the union of the taint marks
   from memory address start to start + size - 1, and if IMPLICIT is
   defined the taint marks for the base and index registers used to
   access memory
*/
void TaintForMemory(ADDRINT start, ADDRINT size, REG baseReg, REG indexReg,
		bitset *set, unsigned int opcode,  unsigned int to_profile) {
	//to_profile always one

	//profiling marks
	if (profiling_marks && to_profile) {
		//prof_log << "opcode:" << LEVEL_CORE::OPCODE_StringShort(opcode) << "#";
		prof_log << "opcode:" << std::dec << opcode << "#";
	}
	const char *marks_sep = "marks:";

	// need to clear out set incase there are preexisting values
	bitset_reset(set);

	//profiling marks
	if (profiling_marks && to_profile) {
		prof_log << marks_sep << bitset_str(set);
		marks_sep = "*";
	}

	int count = 0;
	for (ADDRINT addr = start; addr < start + size; addr++) {
		map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);
		if (memTaintMap.end() != iter) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << marks_sep << bitset_str(iter->second);
				marks_sep = "*";
			}
			bitset_union(set, iter->second);

			if(profiling_markop && to_profile){
				if(word){
					if((count % word_size)==0){
						prof_stream << bitset_str(iter->second);
					}
				}
				else{
					prof_stream << bitset_str(iter->second);
				}
			}
		}
		count++;
	}

#ifdef TRACE
	const char *sep = "";
	if (tracing) {
		log << "\t-" << std::hex << start << "-" << std::hex << start + size - 1
				<< "[";
		for (int i = 0; i < (int) set->nbits; i++) {
			if (bitset_test_bit(set, i)) {
				log << sep << i;
				sep = ", ";
			}
		}
		log << "]\n";
		log.flush();
	}
#endif

#ifdef IMPLICIT
	if (REG_valid(baseReg)) {
		map<REG, bitset *>::iterator iter = regTaintMap.find(baseReg);
		if (regTaintMap.end() != iter) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << marks_sep << bitset_str(iter->second);
				marks_sep = "*";
			}
			bitset_union(set, iter->second);

			if(profiling_markop && to_profile){
				prof_stream << bitset_str(iter->second);
			}

#ifdef TRACE
			if (tracing) {
				sep = "";
				log << ", " << REG_StringShort(baseReg) << "[";
				for (int i = 0; i < (int) iter->second->nbits; i++) {
					if (bitset_test_bit(iter->second, i)) {
						log << sep << i;
						sep = ", ";
					}
				}
				log << "]\n";
				log.flush();
			}
#endif

		}
	}

	if (REG_valid(indexReg)) {
		map<REG, bitset *>::iterator iter = regTaintMap.find(indexReg);
		if (regTaintMap.end() != iter) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << marks_sep << bitset_str(iter->second);
				marks_sep = "*";
			}
			bitset_union(set, iter->second);

			if(profiling_markop && to_profile){
				prof_stream << bitset_str(iter->second);
			}

#ifdef TRACE
			if (tracing) {
				sep = "";
				log << ", " << REG_StringShort(baseReg) << "[";
				for (int i = 0; i < (int) iter->second->nbits; i++) {
					if (bitset_test_bit(iter->second, i)) {
						log << sep << i;
						sep = ", ";
					}
				}
				log << "]\n";
				log.flush();
			}
#endif

		}
	}
#endif

	//profiling marks
	if (profiling_marks && to_profile) {
		prof_log << "#";
		//profile taint mark operation, u stands for union
		prof_log << "u#";
	}

	const char *memory_sep = "memory:";

	for (ADDRINT addr = start; addr < start + size; addr++) {
		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << memory_sep << std::hex << addr;
			memory_sep = "*";
		}
	}

	//profiling marks
	if (profiling_marks && to_profile) {
		//profile log flush
		prof_log << "\n";
		prof_log.flush();
	}

}


/*
   sets the taint marks associated with the dest register to the union
   of the bitsets passed in the varargs parameter
 */
void SetTaintForRegister(REG dest, unsigned int opcode, unsigned int to_profile, int numOfArgs, ...) {
	va_list ap;
	bitset *src;
	int i;

	if (LEVEL_BASE::REG_ESP == dest || LEVEL_BASE::REG_EBP == dest) {
		//prof_log << "skip\n";
		return;
	}

	//profiling marks
	if (profiling_marks && to_profile) {
		//prof_log << "opcode:" << LEVEL_CORE::OPCODE_StringShort(opcode) << "#";
		prof_log << "opcode:" << std::dec << opcode << "#";
	}
	const char *marks_sep = "marks:";

	bitset *tmp = bitset_init(NUMBER_OF_TAINT_MARKS);

	va_start(ap, numOfArgs);
	for (i = 0; i < numOfArgs; i++) {
		src = va_arg(ap, bitset *);
		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << marks_sep << bitset_str(src);
			marks_sep = "*";
		}
		bitset_union(tmp, src);
	}
	va_end(ap);

	// control flow
	bitset *controlTaint = bitset_init(NUMBER_OF_TAINT_MARKS);
	for (map<ADDRINT, bitset *>::iterator iter = controlTaintMap.begin();
			iter != controlTaintMap.end(); iter++) {
		//profiling marks
		if(profiling_marks && to_profile){
			prof_log << marks_sep << "cf=" << bitset_str(iter->second);
			marks_sep = "*";
		}
		if(profiling_markop && to_profile){
			prof_stream << bitset_str(iter->second);
		}
		bitset_union(controlTaint, iter->second);

	}
	bitset_union(tmp, controlTaint);

	//logging here such that control flow can be included
	if(profiling_markop && to_profile){
		prof_stream << std::dec << opcode;
		map<string, int>::iterator profiling_it = profilingMap.find(prof_stream.str());
		if (profilingMap.end() != profiling_it) {
			//prof_log << profiling_it->second << "\n";
			profiling_it->second++;
		}
		else{
			//prof_log << "1\n";
			profilingMap[prof_stream.str()]=1;
		}
		//prof_log << prof_stream.str() << "\n";
		prof_stream.str("");
	}

	/* This is where we account for subregisters */
	/*
	 This isn't totally complete yet.  For example edi and esi are not
	 included and setting [A|B|C|D]X won't set the super or subregisters
	 */

	//profiling marks
	if (profiling_marks && to_profile) {
		prof_log << "#";
		//profile taint mark operation, u stands for union
		prof_log << "u#";
	}
	const char *registers_sep = "registers:";

	//eax
	if (LEVEL_BASE::REG_EAX == dest) {
		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << registers_sep
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AX) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AH) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AL);
			registers_sep = "*";
		}

		//ax
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_AX)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_AX], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_AX] = bitset_copy(tmp);
		}

		//ah
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_AH)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_AH], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_AH] = bitset_copy(tmp);
		}

		//al
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_AL)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_AL], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_AL] = bitset_copy(tmp);
		}
	}

	//ebx
	else if (LEVEL_BASE::REG_EBX == dest) {

		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << registers_sep
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BX) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BH) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BL);
			registers_sep = "*";
		}

		//bx
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_BX)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_BX], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_BX] = bitset_copy(tmp);
		}

		//bh
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_BH)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_BH], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_BH] = bitset_copy(tmp);
		}

		//bl
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_BL)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_BL], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_BL] = bitset_copy(tmp);
		}
	}

	//ecx
	else if (LEVEL_BASE::REG_ECX == dest) {

		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << registers_sep
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CX) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CH) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CL);
			registers_sep = "*";
		}

		//cx
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_CX)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_CX], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_CX] = bitset_copy(tmp);
		}

		//ch
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_CH)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_CH], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_CH] = bitset_copy(tmp);
		}

		//cl
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_CL)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_CL], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_CL] = bitset_copy(tmp);
		}
	}

	//edx
	else if (LEVEL_BASE::REG_EDX == dest) {

		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << registers_sep
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DX) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DH) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DL);
			registers_sep = "*";
		}

		//dx
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_DX)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_DX], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_DX] = bitset_copy(tmp);
		}

		//dh
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_DH)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_DH], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_DH] = bitset_copy(tmp);
		}

		//dl
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_DL)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_DL], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_DL] = bitset_copy(tmp);
		}
	} else if (LEVEL_BASE::REG_AX == dest) {
		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << registers_sep
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AH) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AL);
			registers_sep = "*";
		}

		//ah
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_AH)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_AH], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_AH] = bitset_copy(tmp);
		}

		//al
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_AL)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_AL], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_AL] = bitset_copy(tmp);
		}
	} else if (LEVEL_BASE::REG_BX == dest) {
		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << registers_sep
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BH) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BL);
			registers_sep = "*";
		}

		//bh
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_BH)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_BH], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_BH] = bitset_copy(tmp);
		}

		//bl
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_BL)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_BL], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_BL] = bitset_copy(tmp);
		}
	} else if (LEVEL_BASE::REG_CX == dest) {
		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << registers_sep
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CH) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CL);
			registers_sep = "*";
		}

		//ch
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_CH)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_CH], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_CH] = bitset_copy(tmp);
		}

		//cl
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_CL)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_CL], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_CL] = bitset_copy(tmp);
		}
	} else if (LEVEL_BASE::REG_DX == dest) {
		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << registers_sep
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DH) << "*"
					<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DL);
			registers_sep = "*";
		}

		//dh
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_DH)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_DH], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_DH] = bitset_copy(tmp);
		}

		//dl
		if (regTaintMap.end() != regTaintMap.find(LEVEL_BASE::REG_DL)) {
			bitset_set_bits(regTaintMap[LEVEL_BASE::REG_DL], tmp);
		} else {
			regTaintMap[LEVEL_BASE::REG_DL] = bitset_copy(tmp);
		}
	}

	//profiling marks
	if (profiling_marks && to_profile) {
		prof_log << registers_sep << LEVEL_BASE::REG_StringShort(dest);
		prof_log << "\n";
		prof_log.flush();
	}

	//taking care here of the whole register
	if (regTaintMap.end() != regTaintMap.find(dest)) {
		bitset_set_bits(regTaintMap[dest], tmp);
	} else {
		regTaintMap[dest] = bitset_copy(tmp);
	}

#ifdef TRACE
	if (tracing) {
		const char *sep = "";
		log << ", " << REG_StringShort(dest) << "[";
		bitset *set = regTaintMap[dest];
		for (int i = 0; i < (int) set->nbits; i++) {
			if (bitset_test_bit(set, i)) {
				log << sep << i;
				sep = ", ";
			}
		}
		log << "] <- cf[";

		sep = "";
		for (int i = 0; i < (int) controlTaint->nbits; i++) {
			if (bitset_test_bit(controlTaint, i)) {
				log << sep << i;
				sep = ", ";
			}
		}
		log << "]\n";
		log.flush();
	}

#endif

	bitset_free(tmp);
	bitset_free(controlTaint);
}

/* Clears the taint marks associated with a register */
void ClearTaintForRegister(REG reg, unsigned int opcode, unsigned int to_profile) {

	//profile marks
	if (profiling_marks && to_profile) {
		//prof_log << "opcode:" << LEVEL_CORE::OPCODE_StringShort(opcode) << "#";
		prof_log << "opcode:" << std::dec << opcode << "#";
	}

	const char *marks_sep = "marks:";

	// control flow
	bitset *controlTaint = bitset_init(NUMBER_OF_TAINT_MARKS);

	//profile marks
	if(profiling_marks && to_profile){
		prof_log << marks_sep << bitset_str(controlTaint);
		marks_sep = "*";
	}

	for (map<ADDRINT, bitset *>::iterator iter = controlTaintMap.begin();
			iter != controlTaintMap.end(); iter++) {
		if(profiling_marks && to_profile){
			prof_log << marks_sep << "cf=" << bitset_str(iter->second);
			marks_sep = "*";
		}
		if(profiling_markop && to_profile){
			prof_stream << bitset_str(iter->second);
		}
		bitset_union(controlTaint, iter->second);
	}

	//logging here such that control flow can be included
	if(profiling_markop && to_profile){
		prof_stream << std::dec << opcode;
		map<string, int>::iterator profiling_it = profilingMap.find(prof_stream.str());
		if (profilingMap.end() != profiling_it) {
			//prof_log << profiling_it->second << "\n";
			profiling_it->second++;
		}
		else{
			//prof_log << "1\n";
			profilingMap[prof_stream.str()]=1;
		}
		//prof_log << prof_stream.str() << "\n";
		prof_stream.str("");
	}

	//profiling marks
	if (profiling_marks && to_profile) {
		prof_log << "#";
		//profile taint mark operation, u stands for union
		prof_log << "u#";
	}

	const char *registers_sep = "registers:";

	//eax
	if (LEVEL_BASE::REG_EAX == reg) {
		//ax
		map<REG, bitset *>::iterator iter_ax = regTaintMap.find(
				LEVEL_BASE::REG_AX);
		if (regTaintMap.end() != iter_ax) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AX);
				registers_sep = "*";
			}
			bitset_set_bits(iter_ax->second, controlTaint);
		}

		//ah
		map<REG, bitset *>::iterator iter_ah = regTaintMap.find(
				LEVEL_BASE::REG_AH);
		if (regTaintMap.end() != iter_ah) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AH);
				registers_sep = "*";
			}
			bitset_set_bits(iter_ah->second, controlTaint);
		}

		//al
		map<REG, bitset *>::iterator iter_al = regTaintMap.find(
				LEVEL_BASE::REG_AL);
		if (regTaintMap.end() != iter_al) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AL);
				registers_sep = "*";
			}
			bitset_set_bits(iter_al->second, controlTaint);
		}
	}
	//ebx
	else if (LEVEL_BASE::REG_EBX == reg) {

		//bx
		map<REG, bitset *>::iterator iter_bx = regTaintMap.find(
				LEVEL_BASE::REG_BX);
		if (regTaintMap.end() != iter_bx) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BX);
				registers_sep = "*";
			}
			bitset_set_bits(iter_bx->second, controlTaint);
		}

		//bh
		map<REG, bitset *>::iterator iter_bh = regTaintMap.find(
				LEVEL_BASE::REG_BH);
		if (regTaintMap.end() != iter_bh) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BH);
				registers_sep = "*";
			}
			bitset_set_bits(iter_bh->second, controlTaint);
		}

		//bl
		map<REG, bitset *>::iterator iter_bl = regTaintMap.find(
				LEVEL_BASE::REG_BL);
		if (regTaintMap.end() != iter_bl) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BL);
				registers_sep = "*";
			}
			bitset_set_bits(iter_bl->second, controlTaint);
		}
	}
	//ecx
	else if (LEVEL_BASE::REG_ECX == reg) {
		//cx
		map<REG, bitset *>::iterator iter_cx = regTaintMap.find(
				LEVEL_BASE::REG_CX);
		if (regTaintMap.end() != iter_cx) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CX);
				registers_sep = "*";
			}
			bitset_set_bits(iter_cx->second, controlTaint);
		}

		//ch
		map<REG, bitset *>::iterator iter_ch = regTaintMap.find(
				LEVEL_BASE::REG_CH);
		if (regTaintMap.end() != iter_ch) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CH);
				registers_sep = "*";
			}
			bitset_set_bits(iter_ch->second, controlTaint);
		}

		//cl
		map<REG, bitset *>::iterator iter_cl = regTaintMap.find(
				LEVEL_BASE::REG_CL);
		if (regTaintMap.end() != iter_cl) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CL);
				registers_sep = "*";
			}
			bitset_set_bits(iter_cl->second, controlTaint);
		}
	}

	//edx
	else if (LEVEL_BASE::REG_EDX == reg) {

		//dx
		map<REG, bitset *>::iterator iter_dx = regTaintMap.find(
				LEVEL_BASE::REG_DX);
		if (regTaintMap.end() != iter_dx) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DX);
				registers_sep = "*";
			}
			bitset_set_bits(iter_dx->second, controlTaint);
		}

		//dh
		map<REG, bitset *>::iterator iter_dh = regTaintMap.find(
				LEVEL_BASE::REG_DH);
		if (regTaintMap.end() != iter_dh) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DH);
				registers_sep = "*";
			}
			bitset_set_bits(iter_dh->second, controlTaint);
		}

		//dl
		map<REG, bitset *>::iterator iter_dl = regTaintMap.find(
				LEVEL_BASE::REG_DL);
		if (regTaintMap.end() != iter_dl) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DL);
				registers_sep = "*";
			}
			bitset_set_bits(iter_dl->second, controlTaint);
		}

	} else if (LEVEL_BASE::REG_AX == reg) {
		//ah
		map<REG, bitset *>::iterator iter_ah = regTaintMap.find(
				LEVEL_BASE::REG_AH);
		if (regTaintMap.end() != iter_ah) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AH);
				registers_sep = "*";
			}
			bitset_set_bits(iter_ah->second, controlTaint);
		}

		//al
		map<REG, bitset *>::iterator iter_al = regTaintMap.find(
				LEVEL_BASE::REG_AL);
		if (regTaintMap.end() != iter_al) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_AL);
				registers_sep = "*";
			}
			bitset_set_bits(iter_al->second, controlTaint);
		}
	} else if (LEVEL_BASE::REG_BX == reg) {
		//bh
		map<REG, bitset *>::iterator iter_bh = regTaintMap.find(
				LEVEL_BASE::REG_BH);
		if (regTaintMap.end() != iter_bh) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BH);
				registers_sep = "*";
			}
			bitset_set_bits(iter_bh->second, controlTaint);
		}

		//bl
		map<REG, bitset *>::iterator iter_bl = regTaintMap.find(
				LEVEL_BASE::REG_BL);
		if (regTaintMap.end() != iter_bl) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_BL);
				registers_sep = "*";
			}
			bitset_set_bits(iter_bl->second, controlTaint);
		}
	} else if (LEVEL_BASE::REG_CX == reg) {
		//ch
		map<REG, bitset *>::iterator iter_ch = regTaintMap.find(
				LEVEL_BASE::REG_CH);
		if (regTaintMap.end() != iter_ch) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CH);
				registers_sep = "*";
			}
			bitset_set_bits(iter_ch->second, controlTaint);
		}

		//cl
		map<REG, bitset *>::iterator iter_cl = regTaintMap.find(
				LEVEL_BASE::REG_CL);
		if (regTaintMap.end() != iter_cl) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_CL);
				registers_sep = "*";
			}
			bitset_set_bits(iter_cl->second, controlTaint);
		}
	} else if (LEVEL_BASE::REG_DX == reg) {
		//dh
		map<REG, bitset *>::iterator iter_dh = regTaintMap.find(
				LEVEL_BASE::REG_DH);
		if (regTaintMap.end() != iter_dh) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DH);
				registers_sep = "*";
			}
			bitset_set_bits(iter_dh->second, controlTaint);
		}

		//dl
		map<REG, bitset *>::iterator iter_dl = regTaintMap.find(
				LEVEL_BASE::REG_DL);
		if (regTaintMap.end() != iter_dl) {
			//profiling marks
			if (profiling_marks && to_profile) {
				prof_log << registers_sep
						<< LEVEL_BASE::REG_StringShort(LEVEL_BASE::REG_DL);
				registers_sep = "*";
			}
			bitset_set_bits(iter_dl->second, controlTaint);
		}
	}

	map<REG, bitset *>::iterator iter = regTaintMap.find(reg);
	if (regTaintMap.end() != iter) {
		//profiling marks
		if (profiling_marks && to_profile) {
			prof_log << registers_sep << LEVEL_BASE::REG_StringShort(reg);
			registers_sep = "*";
		}
		bitset_set_bits(iter->second, controlTaint);
	}

	//profiling marks
	if (profiling_marks && to_profile) {
		prof_log << "\n";
		prof_log.flush();
	}

#ifdef TRACE
	if (tracing) {
		const char *sep = "";
		log << "\t" << REG_StringShort(reg) << "  <- cf[";
		sep = "";
		for (int i = 0; i < (int) controlTaint->nbits; i++) {
			if (bitset_test_bit(controlTaint, i)) {
				log << sep << i;
				sep = ", ";
			}
		}
		log << "]\n";
		log.flush();
	}
#endif

	bitset_free(controlTaint);
}

/* Set the taint marks associated with the memory range to the union
   of the bitsets passed in the varargs parameter
*/
void SetTaintForMemory(ADDRINT start, ADDRINT size, unsigned int opcode, unsigned int to_profile, int numOfArgs, ...)
{
  va_list ap;
  bitset *src;
  int i;

  bitset *tmp = bitset_init(NUMBER_OF_TAINT_MARKS);

  //profiling marks
  if(profiling_marks && to_profile){
	  //prof_log << "opcode:" << LEVEL_CORE::OPCODE_StringShort(opcode) << "#";
	  prof_log << "opcode:" << std::dec << opcode << "#";
  }
  const char *marks_sep = "marks:";

  va_start(ap, numOfArgs);

    for(i = 0; i < numOfArgs; i++) {
        src = va_arg(ap, bitset *);
        //profiling marks
        if(profiling_marks && to_profile){
            prof_log << marks_sep << bitset_str(src);
            marks_sep = "*";
        }
        bitset_union(tmp, src);
    }

  va_end(ap);

  // control flow
  bitset *controlTaint = bitset_init(NUMBER_OF_TAINT_MARKS);
  for(map<ADDRINT, bitset *>::iterator iter = controlTaintMap.begin();
        iter != controlTaintMap.end(); iter++) {
			//profiling marks
			if(profiling_marks && to_profile){
				prof_log << marks_sep << "cf=" << bitset_str(iter->second);
				marks_sep = "*";
			}
			if(profiling_markop && to_profile){
				prof_stream << bitset_str(iter->second);
			}

            bitset_union(controlTaint, iter->second);
        }

  bitset_union(tmp, controlTaint);

  //logging here such that control flow can be included
  if(profiling_markop && to_profile){
	  prof_stream << std::dec << opcode;
		map<string, int>::iterator profiling_it = profilingMap.find(prof_stream.str());
		if (profilingMap.end() != profiling_it) {
			//prof_log << profiling_it->second << "\n";
			profiling_it->second++;
		}
		else{
			//prof_log << "1\n";
			profilingMap[prof_stream.str()]=1;
		}
  	  //prof_log << prof_stream.str() << "\n";
  	  prof_stream.str("");
  }

  //profiling marks
  if(profiling_marks && to_profile){
	  prof_log << "#";
	  //profile taint mark operation, u stands for union
	  prof_log << "u#";
  }
  const char *memory_sep = "memory:";

  if(profiling_marks){
	  prof_log << "start:" << std::hex << start << "sized:" << std::dec << size << "sizeh:" << std::hex << size;
  }

  for(ADDRINT addr = start; addr < start + size; addr++) {
	//profiling marks
	if(profiling_marks && to_profile){
		prof_log << memory_sep << std::hex << addr;
		memory_sep = "*";
	}
    if(memTaintMap.end() != memTaintMap.find(addr)) {
      //the address was already in the taint map
      bitset_set_bits(memTaintMap[addr], tmp);
    }
    else {
      //first time I have this address
      memTaintMap[addr] = bitset_copy(tmp);
    }
  }

  //profiling marks
  if(profiling_marks && to_profile){
	  //profile log flush
	  prof_log << "\n";
	  prof_log.flush();
  }

#ifdef TRACE
  if(tracing) {
     const char *sep = "";
      log <<"\t" << std::hex << start << "-" << std::hex << start + size - 1 << " <- cf[";
    for(int i = 0; i < (int)tmp->nbits; i++) {
      if(bitset_test_bit(tmp, i)) {
          log << sep << i;
      sep = ", ";
      }
    }
    log << "] <- cf[";

    sep = "";
    for(int i = 0; i < (int)controlTaint->nbits; i++) {
      if(bitset_test_bit(controlTaint, i)) {
          log << sep << i;
          sep = ", ";
      }
    }
    log << "]\n";
  }
#endif

  bitset_free(tmp);
  bitset_free(controlTaint);
}

/* Clears taint marks associted with the range of memory */
void ClearTaintForMemory(ADDRINT start, ADDRINT size, unsigned int opcode, unsigned int to_profile)
{

  //profiling marks
  if(profiling_marks && to_profile){
		//prof_log << "opcode:" << LEVEL_CORE::OPCODE_StringShort(opcode) << "#";
	  	prof_log << "opcode:" << std::dec << opcode << "#";
  }

  const char *marks_sep = "marks:";

  // control flow
    bitset *controlTaint = bitset_init(NUMBER_OF_TAINT_MARKS);

	//profile marks
	if(profiling_marks  && to_profile){
		prof_log << marks_sep << bitset_str(controlTaint);
		marks_sep = "*";
	}

    for(map<ADDRINT, bitset *>::iterator iter = controlTaintMap.begin();
          iter != controlTaintMap.end(); iter++) {
		if(profiling_marks  && to_profile){
			prof_log << marks_sep << "cf=" << bitset_str(iter->second);
			marks_sep = "*";
		}
		if(profiling_markop && to_profile){
			prof_stream << bitset_str(iter->second);
		}
          bitset_union(controlTaint, iter->second);
      }

    //logging here such that control flow can be included
    if(profiling_markop && to_profile){
  	  prof_stream << std::dec << opcode;
		map<string, int>::iterator profiling_it = profilingMap.find(prof_stream.str());
		if (profilingMap.end() != profiling_it) {
			///prof_log << profiling_it->second << "\n";
			profiling_it->second++;
		}
		else{
			//prof_log << "1\n";
			profilingMap[prof_stream.str()]=1;
		}
  	  //prof_log << prof_stream.str() << "\n";
  	  prof_stream.str("");
    }

	//profiling marks
	if (profiling_marks  && to_profile) {
		prof_log << "#";
		//profile taint mark operation, u stands for union
		prof_log << "u#";
	}

  const char *memory_sep = "memory:";

  for(ADDRINT addr = start; addr < start + size; addr++) {

    map<ADDRINT, bitset *>::iterator iter = memTaintMap.find(addr);
    if(memTaintMap.end() != iter) {
      //profiling marks
      if(profiling_marks && to_profile){
    	  prof_log << memory_sep << std::hex << addr;
    	  memory_sep = "*";
      }
      bitset_set_bits(iter->second, controlTaint);
    }
  }

  //profiling marks
  if(profiling_marks && to_profile){
		prof_log << "\n";
		prof_log.flush();
  }

#ifdef TRACE
  if(tracing) {
    const char *sep = "";
      log <<"\t" << std::hex << start << "-" << std::hex << start + size - 1 << " <- cf[";
    sep = "";
    for(int i = 0; i < (int)controlTaint->nbits; i++) {
      if(bitset_test_bit(controlTaint, i)) {
          log << sep << i;
	sep = ", ";
      }
    }
    log << "]\n";
    log.flush();
  }
#endif

  bitset_free(controlTaint);
}


