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
#include "regex-repeat-matcher.h"

#include "logging.h"

INIT_LOGGER ("RegexPatternListMatcher");

using namespace std;

namespace ndn
{

namespace regex
{
  RegexPatternListMatcher::RegexPatternListMatcher(const string expr, RegexBRManager* backRefManager)
    :RegexMatcher(expr, EXPR_PATTERNLIST, backRefManager)
  {
    _LOG_DEBUG ("Enter RegexPatternListMatcher Constructor: " << m_expr);
    if(!compile())
      throw RegexException("RegexPatternListMatcher Constructor: Cannot compile the regex");
  }
  
  bool 
  RegexPatternListMatcher::compile()
  {
    _LOG_DEBUG ("Enter RegexPatternListMatcher::Compile()");

    const int len = m_expr.size();
    int index = 0;
    int subHead = index;
    
    while(index < len){
      subHead = index;

      if(!extractPattern(subHead, &index))
	return false;
    }
    return true;

  }

  bool 
  RegexPatternListMatcher::extractPattern(int index, int* next)
  {
    _LOG_DEBUG ("Enter RegexPatternListMatcher::ExtractPattern()");

    string errMsg = "Error: RegexPatternListMatcher.ExtractSubPattern(): ";
    
    const int start = index;
    int end = index;
    int indicator = index;
    RegexRepeatMatcher * matcher = NULL;

    _LOG_DEBUG ("m_expr: " << m_expr << " index: " << index);

    switch(m_expr[index]){
    case '(':
      index++;
      index = extractSubPattern('(', ')', index);
      indicator = index;
      end = extractRepetition(index);
      break;
      

    case '<':
      index++;
      index = extractSubPattern('<', '>', index);
      indicator = index;
      end = extractRepetition(index);
      _LOG_DEBUG ("start: " << start << " end: " << end << " indicator: " << indicator);
      break;

    default:
      throw RegexException("Error: unexpected syntax");
    }

//     _LOG_DEBUG("Generate repeat: " << m_expr.substr(start, end) << " start: " << start << " end: " << end << " indicator: " << indicator);
    matcher = new RegexRepeatMatcher(m_expr.substr(start, end - start), m_backRefManager, indicator - start);
    m_matcherList.push_back(matcher);

    *next = end;

    return true;
  }
  
  int 
  RegexPatternListMatcher::extractSubPattern(const char left, const char right, int index)
  {
    _LOG_DEBUG ("Enter RegexPatternListMatcher::ExtractSubPattern()");

    int lcount = 1;
    int rcount = 0;

    while(lcount > rcount){

      if(index >= m_expr.size())
	throw RegexException("Error: parenthesis mismatch");

      if(left == m_expr[index])
        lcount++;

      if(right == m_expr[index])
        rcount++;

      index++;
    }
    return index;
  }

  int 
  RegexPatternListMatcher::extractRepetition(int index)
  {
    _LOG_DEBUG ("Enter RegexPatternListMatcher::ExtractRepetition()");

    int exprSize = m_expr.size();

    _LOG_DEBUG ("expr: " << m_expr << " index: " << index << " char: " << (index == exprSize ? 0 : m_expr[index]));

    string errMsg = "Error: RegexPatternListMatcher.ExtractRepetition(): ";
    
    if(index == exprSize)
      return index;
    
    if(('+' == m_expr[index] || '?' == m_expr[index] || '*' == m_expr[index])){
      return ++index;
    }

    
    if('{' == m_expr[index]){
      while('}' != m_expr[index]){
        index++;
        if(index == exprSize)
          break;
      }
      if(index == exprSize)
        throw RegexException(errMsg + "Missing right brace bracket");
      else
        return ++index;
    }
    else{
      _LOG_DEBUG ("return index: " << index);
      return index;
    }
  }

}//regex

}//ndn
