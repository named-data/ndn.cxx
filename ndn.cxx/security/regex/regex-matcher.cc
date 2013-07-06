/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{
  RegexMatcher::~RegexMatcher()
  {
    vector<RegexMatcher*>::iterator it = m_matcherList.begin();
    for(; it != m_matcherList.end(); it++)
	delete *it;
  }

  bool RegexMatcher::Compile()
  {
    const int len = expr.size();
    int index = m_offset;
    int subHead = index;

    while(index < len){
      try{
        index = ExtractSubPattern(index);

        string subExpr = expr.substr(subHead, index - subHead);
        

        m_matcherList.push_back(RegexMatcher(expr.substr(subHead, index - subHead), subHead));
        subHead = index;
      }
      catch(RegexException & e){
        cerr << e.GetMsg() << endl;
        exit(-1);
      }
    }
  }

  bool RegexMatcher::Match(Name name)
  {
    return false;
  }

  int RegexMatcher::ExtractSubPattern(int index)
  {
    bool head = (index == 0 ? true : false);
    int end = index;

    switch(m_expr[index]){
    case '^':
      if(head){
        index++;
        end = ExtractSubPattern(index);
        return CheckDollar(end);
      }
      else
        throw RegexException("Error: ^ is not the first");

    case '(':
      index++;
      index = ExtractBackRef(index);
      end = ExtractRepetition(index);
      return CheckDollar(end);

    case '!':
      index++;
      end = ExtractSubPattern(index);
      return CheckDollar(end);

    case '<':
      index++;
      index = ExtractComponent(index);
      end = ExtractRepetition(index);
      return CheckDollar(end);

    default:
      throw RegexException("Error: unexpected syntax");
    }
  }

  int RegexMatcher::ParseDollar(int index)
  {
    if('$' == m_expr[index]){

      if(len - 1 == index)
        return len;
      else
        throw RegexException("Error: pattern after $");
    }
    else
      return index;
  }

  int RegexMatcher::ExtractBackRef(int index)
  {
    int lcount = 1;
    int rcount = 0;

    while(lcount > rcount){
      switch(m_expr[index]){
      case '(':
        lcount++;
        break;

      case ')':
        rcount++;
        break;

      case 0:
        throw RegexException("Error: parenthesis mismatch");
        break;
      }

      index++;
    }
    return index;
  }

  int RegexMatcher::ExtractComponent(int index)
  {
    int lcount = 1;
    int rcount = 0;

    while(lcount > rcount){
      switch(m_expr[index]){
      case '<':
        lcount++;
        break;

      case '>':
        rcount++;
        break;

      case 0:
        throw RegexException("Error: square brackets mismatch");
        break;
      }
      index++;

    }
    return index;

  }

  RegexExprType RegexMatcher::GetRegexExprType(string expr, RegexExprType parentType){
    int first = 0;
    int last = expr.size() - 1;

    // Top level expression
    if(parentType == EXPR_TOP){
      if(expr[first] == '^'){
        if(expr[last] == '$')
          return EXPR_HEAD_TAIL;
        else
          return EXPR_HEAD;
      }
      else{
        if(expr[last] == '$')
          return EXPR_TAIL;
        else
          return EXPR_PATTERN;
      }
    }
  }

  /**
   * @brief check if the pattern match the part of name
   * @param name name against which the pattern is matched
   * @param offset starting index of matching
   * @param len number of components to be matched
   */

  bool RegexMatcher::Match(Name name, const int & offset, const int & len)
  {
    return RecursiveMatch(0, name, offset, len);
  }

  bool RegexMatcher::RecursiveMatch(int mId, Name name, const int & offset, const int & len)
  {
    int tried = 0;

    if(mId >= m_matcherList.size()){
      if(len != 0)
	return false;
      else
	return true;

    RegexMatcher * matcher = m_matcherList[mId];

    while(tried <= len){
      if(matcher->Match(name, offset, tried)){
	if(!RecursiveMatch(mId + 1, name, offset + tried, len - tried))
	  tried++;
	else
	  return true;
      }
    }

    return false;
  }

}//regex

}//ndn
