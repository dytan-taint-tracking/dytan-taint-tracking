#ifndef _BASIC_BLOCK_H
#define _BASIC_BLOCK_H

#include "pin.H"

#include "sys/types.h"

#include <cstdio>
#include <set>
#include <queue>
#include <map>

using namespace std;

class BasicBlock {

public:

	queue<ADDRINT> body;
	int visited;
	int isEntry;
	const char * routineCalled;

//The following two variables are CFG node pointers. Successors are basic blocks
//where control is passed to, while predecessors are back pointers where control
//was passed from
	set<void *> successors;
	set<void *> predecessors;

//These variables are dominance pointers. The map of "dominated" nodes refer to all
//nodes that are dominated by the current block, both immediately and recursively
//The "Dominator" variable is the pointer to the immmediate dominator of the current
//node
//Finally, the immediatelyDominated map set is a subset of the dominated set, where
//the nodes are only those immediately dominated by the current node
//NOTE: I understand that dominance isn't be used as of quite yet, but I've implemented its
//functionality anyway.
	map<ADDRINT, BasicBlock *> dominated;
	BasicBlock * Dominator;
	map<ADDRINT, BasicBlock *> immediatelyDominated;

//Similarly these variables, are post-dominance pointers. The map of postDominated nodes
//are those immmediately and recursively postDominated by the current node.
//The PostDominator is a pointer to the postDominating node of the current one.
//Finally, as requested, is the "immediatelyPostDominated" map subset.
	map<ADDRINT, BasicBlock *> postDominated;
	BasicBlock * PostDominator;
	map<ADDRINT, BasicBlock *> immediatelyPostDominated;

	ADDRINT startingAddress;
	ADDRINT endingAddress;
	int isPostDominated;

	BasicBlock();
	virtual ~BasicBlock();
	void setRoutineCalled(const char * routineName);
	void visitNode();
	void revisitNode();
	int getVisited();
	void setAsEntryNode();
	int getIsEntry();
	void printDetailedInformation(FILE * graphFile);
	void printInformation();
	set<void *> getSuccessors();
	set<void *> getPredecessors();
	void insertPreds(BasicBlock* pBlock);
	void insertBody(ADDRINT address);
	void insertSuccs(BasicBlock* pBlock);
	void setEnding(ADDRINT endAddr);
	ADDRINT getEnding();
	void setStarting(ADDRINT startAddr);
	ADDRINT getStarting();
	void setDominator(BasicBlock * block);
	void setPostDominator(BasicBlock * block);
	BasicBlock * getDominator();
	BasicBlock * getPostDominator();
	BasicBlock * getCommonDominator(BasicBlock * siblingBlock);
	BasicBlock * getCommonPostDominator(BasicBlock * siblingBlock);
	void addImmediateDominator(BasicBlock * newBlock);
	void addImmediatePostDominator(BasicBlock * newBlock);
	void addSuccessorAsDominated(BasicBlock * successor);
	void addPredecessorAsPostDominated(BasicBlock * predecessor);
	map<ADDRINT, BasicBlock *> getdominated();
	map<ADDRINT, BasicBlock *> getPostDominated();
	void passUpDominanceInfo(BasicBlock * newChild);
	void passDownPostDominanceInfo(BasicBlock * newChild);
	void deleteUpDominanceInfo(map<ADDRINT, BasicBlock *> deletableBlocks,
			ADDRINT deletableBlocksParent, ADDRINT lastNodesStarting);
	void deleteDownPostDominanceInfo(map<ADDRINT, BasicBlock *> deletableBlocks,
			ADDRINT deletableBlocksParent, ADDRINT lastNodesStarting);

};
#endif
