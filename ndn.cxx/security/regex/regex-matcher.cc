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
    delete m_backRefManager;

    vector<RegexMatcher*>::iterator it = m_matcherList.begin();
    for(; it != m_matcherList.end(); it++)
	delete *it;
  }

  /**
   * @brief check if the pattern match the part of name
   * @param name name against which the pattern is matched
   * @param offset starting index of matching
   * @param len number of components to be matched
   * @returns true if match succeeds
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
    }
    
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

}//regex

}//ndn
