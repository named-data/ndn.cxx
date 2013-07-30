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

#include "logging.h"

INIT_LOGGER ("RegexMatcher");

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

  /**
   * @brief check if the pattern match the part of name
   * @param name name against which the pattern is matched
   * @param offset starting index of matching
   * @param len number of components to be matched
   * @returns true if match succeeds
   */
  bool 
  RegexMatcher::cMatch(Name name, const int & offset, const int & len)
  {
    _LOG_DEBUG ("Enter RegexMatcher::Match");
    _LOG_DEBUG ("size of matcher list: " << m_matcherList.size());

    m_matchResult = Name();
    if(cRecursiveMatch(0, name, offset, len)){
      for (int i = 0; i < len ; i++)
        m_matchResult.append(name.get(offset+i));
      return true;
    }
    else
      return false;
  }

  bool 
  RegexMatcher::cRecursiveMatch(int mId, Name name, const int & offset, const int & len)
  {
    _LOG_DEBUG ("Enter RegexMatcher::RecursiveMatch");

    int tried = 0;

    if(mId >= m_matcherList.size()){
      if(len != 0)
	return false;
      else
	return true;
    }
    
    RegexMatcher * matcher = m_matcherList[mId];

    while(tried <= len){
      if(matcher->cMatch(name, offset, tried) && cRecursiveMatch(mId + 1, name, offset + tried, len - tried))
        return true;      
      tried++;
    }

    return false;
  }
  

}//regex

}//ndn
