/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-patternlist-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{
  
  bool RegexPatternListMatcher::Compile()
  {
    const int len = expr.size();
    int index = 0;
    int subHead = index;
    
    while(index < len){
      subhead = index;

      if(!ExtractPattern(subhead, &index))
	return false;
    }
    return true;

  }

  bool RegexPatternListMatcher::ExtractPattern(int index, int* next)
  {
    string errMsg = "Error: RegexPatternListMatcher.ExtractSubPattern(): "
    
    const int start = index;
    int end = index;
    int indicator = index;
    RegexMatcher * matcher = NULL;

    switch(m_expr[index]){
    case '(':
      index++;
      index = ExtractSubPattern('(', ')', index);
      indicator = index;
      end = ExtractRepetition(index);
      

    case '<':
      index++;
      index = ExtractSubPattern('<', '>', index);
      indicator = index;
      end = ExtractRepetition(index);

    default:
      throw RegexException("Error: unexpected syntax");
    }

    matcher = new RegexRepeatMatcher(m_expr.substr(start, end), m_backRefManager, indicator);

    if(matcher->Compile()){
      m_matcherList->push_back(matcher);
      *next = end;
      return true;
    }
    else{
      throw RegexException(errMsg + "Cannot compile subpattern " + m_expr);
      return false;
    }
  }
  
  int RegexMatcher::ExtractSubPattern(const char left, const char rightint index)
  {
    int lcount = 1;
    int rcount = 0;

    while(lcount > rcount){

      if(index >= m_expr.size())
	throw RegexException("Error: parenthesis mismatch");

      switch(m_expr[index]){
      case left:
        lcount++;
        break;

      case right:
        rcount++;
        break;
      }

      index++;
    }
    return index;
  }

}//regex

}//ndn
