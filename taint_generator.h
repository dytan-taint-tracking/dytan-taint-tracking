#ifndef _TAINT_GENERATOR_H
#define _TAINT_GENERATOR_H

#include <iostream>
#include <cstdlib>

using namespace std;

class TaintGenerator
{
	int _start;
    int _current;
    int _max;
 public:
    TaintGenerator();
    TaintGenerator(int start, int max);
    ~TaintGenerator();
    virtual int nextTaintMark();
    virtual void setStart(int new_start);
    virtual int getCurrent();
    virtual int getMax();

};

class ConstantTaintGenerator: public TaintGenerator
{
 private:
  int _seed;

 public:
  ConstantTaintGenerator(int seed);
  int nextTaintMark();

};


class RandomSetTaintGenerator: public TaintGenerator
{
 private:
  int _start;
  int _num;

 public:
  RandomSetTaintGenerator(int start, int num);
  int nextTaintMark();

};

#endif
