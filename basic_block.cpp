#include "basic_block.h"

BasicBlock::BasicBlock() {
	visited = 0;
	endingAddress = 0;
	startingAddress=0;
	routineCalled = "";
	isPostDominated = 0;

}

BasicBlock::~BasicBlock(){
}

void BasicBlock::setRoutineCalled(const char * routineName) {
	routineCalled = routineName;
}

void BasicBlock::visitNode() {
	visited = 1;
}

void BasicBlock::revisitNode() {
	visited = 2;
}

int BasicBlock::getVisited() {
	return visited;
}


void BasicBlock::setAsEntryNode() {
	isEntry = 1;
}

int BasicBlock::getIsEntry() {
	return isEntry;
}


void BasicBlock::printDetailedInformation(FILE * graphFile) {

	if (startingAddress == 1) {
		set< void *>::iterator setIterator;
		setIterator = predecessors.begin();
		BasicBlock* parentBlock = (BasicBlock *)(* setIterator);

		fprintf(graphFile, "Node%icall[shape = record, label = \" call to  routine  %s  \" , width = 1, fontsize = 10] ;\n", (uint) parentBlock->startingAddress, routineCalled);
	} else if (startingAddress == 2) {
		fprintf(graphFile, "Node%i [shape = record, label = \"Return Node \" , width = 1, fontsize = 10] ;\n", (uint) startingAddress);//, startingAddress, startingAddress, endingAddress);

	} else if (isEntry == 1) {
		fprintf(graphFile, "Node%i [shape = record, label = \"Entrance Node | {%#x | %#x}  \" , width = 1, fontsize = 10] ;\n", (uint) startingAddress,(uint) startingAddress, (uint) endingAddress);
	} else if (startingAddress == 4) {
		set< void *>::iterator setIterator;
		setIterator = predecessors.begin();
		BasicBlock* parentBlock = (BasicBlock *)(* setIterator);
		fprintf(graphFile, "Node%iIC[shape = record, label = \"Indirect Call  \" , width = 1, fontsize = 10] ;\n", (uint) parentBlock->startingAddress);
	} else if (startingAddress == 5) {
		set< void *>::iterator setIterator;
		setIterator = predecessors.begin();
		BasicBlock* parentBlock = (BasicBlock *)(* setIterator);
		fprintf(graphFile, "Node%iIB[shape = record, label = \"Indirect Branch  \" , width = 1, fontsize = 10] ;\n", (uint) parentBlock->startingAddress);
	} else {
		fprintf(graphFile, "Node%i [shape = record, label = \"Regular Node | {%#x | %#x}  \" , width = 1, fontsize = 10] ;\n", (uint) startingAddress, (uint) startingAddress, (uint) endingAddress);
	}


}

void BasicBlock::printInformation() {


}

set< void * > BasicBlock::getSuccessors() {

	return successors;
}

set<void *> BasicBlock::getPredecessors() {

	return predecessors;
}

void BasicBlock::insertPreds( BasicBlock* pBlock) {
	predecessors.insert(pBlock);
}

void BasicBlock::insertBody(ADDRINT address){
	body.push(address);

}

void BasicBlock::insertSuccs( BasicBlock* pBlock){
	successors.insert(pBlock);
	//cout << "block added to succs" << endl;

}

void BasicBlock::setEnding(ADDRINT endAddr){
	endingAddress = endAddr;
}

ADDRINT BasicBlock::getEnding() {
	return endingAddress;
}

void BasicBlock::setStarting(ADDRINT startAddr){
	startingAddress = startAddr;
}

ADDRINT BasicBlock::getStarting() {
	return startingAddress;
}

void BasicBlock::setDominator(BasicBlock * block) {
	Dominator = block;
}

void BasicBlock::setPostDominator(BasicBlock * block) {
	isPostDominated = 1;
	PostDominator = block;
}

BasicBlock * BasicBlock::getDominator() {
	return Dominator;
}

BasicBlock * BasicBlock::getPostDominator() {
	return PostDominator;
}


BasicBlock * BasicBlock::getCommonDominator(BasicBlock * siblingBlock) {
		//fprintf(stderr, "  looking at %#x \n", getStarting());
		if (dominated[siblingBlock -> getStarting()] != NULL) {//this node is a parent to both siblingBlocks
		//fprintf(stderr, "  found a parent at\n");
			return this;
		} else if (isEntry == 1) {//this means its the entry
			//fprintf(stderr, "  found entry node\n");
			return this;
		} else {
		//fprintf(stderr, "  going up a level \n");
			return Dominator->getCommonDominator(siblingBlock);
		}
}

BasicBlock * BasicBlock::getCommonPostDominator(BasicBlock * siblingBlock) {
		if (postDominated[siblingBlock -> getStarting()] != NULL) {//this node is a parent to both siblingBlocks
		//fprintf(stderr, "  found a post parent at\n");
			return this;
		} else if (getStarting() == 2) {//this means its the return
			return this;
		} else {
		//fprintf(stderr, "  going up a level \n");
			return PostDominator->getCommonPostDominator(siblingBlock);
		}
}

void BasicBlock::addImmediateDominator(BasicBlock * newBlock) {
	immediatelyDominated[newBlock->getStarting()] = newBlock;
}

void BasicBlock::addImmediatePostDominator(BasicBlock * newBlock) {
	immediatelyPostDominated[newBlock->getStarting()] = newBlock;
}

void BasicBlock::addSuccessorAsDominated(BasicBlock * successor) {
		if (successor->getDominator() == NULL) {
		//fprintf(stderr, "  and yes it is the dominant by default \n");
			successor ->setDominator(this);
			addImmediateDominator(successor);
		//fprintf(stderr, "  passing up the new info \n");
			passUpDominanceInfo(successor);
		} else {
		//fprintf(stderr, "  and no, there is another immediate successor...looking for common dominator \n");
			BasicBlock * competingSibling = successor ->getDominator();
			BasicBlock * newDominator = getCommonDominator(successor);
			immediatelyDominated.erase(successor->getStarting());

//fprintf(stderr, " comparint %#x and %#x \n", successor->getStarting(),  bigDominator->getStarting());
			competingSibling->deleteUpDominanceInfo(successor -> getdominated(), successor->getStarting(), newDominator->getStarting());
		//fprintf(stderr, " finished deleting\n");
			successor->setDominator(newDominator);
			newDominator->addImmediateDominator(successor);

		}
}

void BasicBlock::addPredecessorAsPostDominated(BasicBlock * predecessor) {
		//fprintf(stderr, "block: %#x is  adding block %#x \n",getStarting(), predecessor->getStarting());
//		BasicBlock * postDomin = predecessor->getPostDominator();
		if (predecessor->isPostDominated == 0) {
		//fprintf(stderr, "  and yes it is the Postdominant by default \n");
			predecessor ->setPostDominator(this);
			addImmediatePostDominator(predecessor);
		//fprintf(stderr, "  passing down the new info \n");
			passDownPostDominanceInfo(predecessor);
		} else {
		//fprintf(stderr, "  and no, there is another immediate predecessor ...looking for common post dominator \n");
			BasicBlock * competingSibling = predecessor ->getPostDominator();
			BasicBlock * newPostDominator = getCommonPostDominator(predecessor);
			immediatelyPostDominated.erase(predecessor->getStarting());
			competingSibling->deleteDownPostDominanceInfo(predecessor -> getPostDominated(), predecessor->getStarting(), newPostDominator->getStarting());
		//fprintf(stderr, " finished deleting\n");

			predecessor->setPostDominator(newPostDominator);
			newPostDominator->addImmediatePostDominator(predecessor);


		}
}

map<ADDRINT, BasicBlock *> BasicBlock::getdominated() {
	return dominated;
}

map<ADDRINT, BasicBlock *> BasicBlock::getPostDominated() {
	return postDominated;
}

void BasicBlock::passUpDominanceInfo(BasicBlock * newChild) {
	dominated[newChild->getStarting()] = newChild;
		//fprintf(stderr, "  added new info \n");
	if (isEntry == 0) {//if not entry, pass up
		Dominator->passUpDominanceInfo(newChild);
	}

}

void BasicBlock::passDownPostDominanceInfo(BasicBlock * newChild) {
	postDominated[newChild->getStarting()] = newChild;
		//fprintf(stderr, "  added new info \n");
	if (getStarting() != 2) {//if not return, pass up
		PostDominator->passDownPostDominanceInfo(newChild);
	}

}

void BasicBlock::deleteUpDominanceInfo(map <ADDRINT, BasicBlock *> deletableBlocks, ADDRINT deletableBlocksParent, ADDRINT lastNodesStarting) {
//fprintf(stderr, " comparint %#x and %#x \n", startingAddress,  lastNodesStarting);
	if (startingAddress < lastNodesStarting ) {
		dominated.erase(deletableBlocksParent);
		map <ADDRINT, BasicBlock *>::iterator mapIterator;
		for (mapIterator = deletableBlocks.begin(); mapIterator != deletableBlocks.end(); mapIterator++) {
		//fprintf(stderr, "  deleting info from  node:\n");
		printInformation();
		//fprintf(stderr, "  Dominanated node %#x :\n", (ADDRINT(mapIterator -> first)));
		dominated.erase((ADDRINT(mapIterator -> first)));


		}
		if (Dominator) {
		Dominator->deleteUpDominanceInfo(deletableBlocks, deletableBlocksParent, lastNodesStarting);
		}

	}

}

void BasicBlock::deleteDownPostDominanceInfo(map <ADDRINT, BasicBlock *> deletableBlocks, ADDRINT deletableBlocksParent, ADDRINT lastNodesStarting) {

	if (startingAddress !=lastNodesStarting ) {
		//fprintf(stderr, " node is not parent, continue deleting\n");
		postDominated.erase(deletableBlocksParent);
		map <ADDRINT, BasicBlock *>::iterator mapIterator;
		for (mapIterator = deletableBlocks.begin(); mapIterator != deletableBlocks.end(); mapIterator++) {
		//fprintf(stderr, "  deleting info from  node:\n");
		printInformation();
		//fprintf(stderr, "  postDominanated node %#x :\n", (ADDRINT(mapIterator -> first)));
		postDominated.erase((ADDRINT(mapIterator -> first)));


		}
		if (PostDominator)
		PostDominator->deleteDownPostDominanceInfo(deletableBlocks, deletableBlocksParent, lastNodesStarting);

	}

}
