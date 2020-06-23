#include "taint_generator.h"

TaintGenerator::TaintGenerator(){
}

TaintGenerator::~TaintGenerator(){
}

TaintGenerator::TaintGenerator(int start, int max){
	_start = start;
    _current = start;
    _max = max;
}

int TaintGenerator::nextTaintMark() {
	int result = _current;
	if(((_current+1)%_max)==0){
		_current = _start;
	}
	else{
		_current = _current+1;
	}
	return result;
    //int result = (_current)%_max;
    //_current = _current + 1;
    //return result;
}

void TaintGenerator::setStart(int new_start){
	_start = new_start;
}

//current gives the lowest available mark
int TaintGenerator::getCurrent(){
	return _current;
}

int TaintGenerator::getMax(){
	return _max;
}

ConstantTaintGenerator::ConstantTaintGenerator(int seed){
  _seed = seed;
}

int ConstantTaintGenerator::nextTaintMark() {
  return _seed;
}

RandomSetTaintGenerator::RandomSetTaintGenerator(int start, int num){
  _start = start;
  _num = num;
}

int RandomSetTaintGenerator::nextTaintMark() {
  return (rand() % _num) + _start;
}


