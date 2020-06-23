#ifndef _ROUTINE_GRAPH_H
#define _ROUTINE_GRAPH_H

#include "pin.H"

#include "sys/types.h"

#include <cstdio>
#include <fstream>
#include <map>
#include <string>
#include <queue>
#include <set>

#include "basic_block.h"


using namespace std;

class RoutineGraph {

public:

//The 3 variables that make up the useful final bits of the RoutineGraph object
//The head of the linked list
	BasicBlock * EntranceNode;
//The tail of the linked list, this however gets fed in first when calculating post-dominance
	BasicBlock * ReturnNode;
//All The instructions mapped out over the address space of the routine image onto Basic Blocks
	map<ADDRINT, BasicBlock *> addressMap;
//A set of all the basicBlocks, both physically in memory and representative, like indirect branch targets and calls
	set<BasicBlock *> allBlocks;

	FILE * resultsFile;
	FILE * debugFile;

	RoutineGraph(RTN rtn);
	RoutineGraph(RTN rtn, FILE * specifiedResults, FILE * specifiedDebug);
	virtual ~RoutineGraph();
	void initializeRoutineInfo(RTN rtn);

private:
//utility variables
	map<ADDRINT, set<ADDRINT> > branches;
	map<ADDRINT, set<ADDRINT> > targets;
	RTN targetRTN;

//I tweaked around a lot with this function at first, when I was trying to get things to work
//lots of things have changed in it over the course of the program, but the program does seem
//to work correctly
//Well, what I believe is mostly correct; I have made several assumptions on how to implement
//things. For example, I have made special addresses as flags. This can be tempororay.
	void mapper(INS ins, RTN rtn);
	void BlockBuilder(RTN rtn);
	void BranchIns(INS currentIns, BasicBlock * currentBlock);
	BasicBlock * Get_BasicBlock_At(ADDRINT targetAddress);
//This is my post dominance builder,
	void buildPostDominanceTree(BasicBlock * currentBlock,
			queue<BasicBlock *> blockQueue);
//DEPRECATED -- why do I have a dominance tree? Well I got the two confused. I could either go
//back and reverse all my dominance tree functions,...or just keep it and make new postdominance
//functions....if you need dominance info, heres the method to do this
	void buildDominanceTree(BasicBlock * currentBlock,
			queue<BasicBlock *> blockQueue);

};
#endif
