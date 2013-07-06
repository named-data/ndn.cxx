/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "regex-repeat-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{

  bool RegexRepeatMatcher::Compile()
  {
    //TODO
  }

  bool RegexRepeatMatcher::Match(Name name, const int & offset, const int & len)
  {
    int repeat = 0;
    RegexMatcher * matcher = m_matcherList[0];
    
    RecursiveMatch(matcher, repeat, name, offset, len);
  }

  bool RegexRepeatMatcher::RecursiveMatch(RegexMatcher* matcher, 
					  int repeat, 
					  Name, name, 
					  const int & offset, 
					  const int &len)
  {
    int tried = 0;
    if(repeat > m_repeatMax)
      return true;
    

    if(matcher->Match(name, offset, tried)){
      repeat++;
      if(RecursiveMatch(matcher, repeat, name, offset + tried, len - tried))
	return true;
    }
    else{
      if(repeat < m_repeatMin)
	return false;
      else
	return true;
    }
  
  }

}//regex

}//ndn
