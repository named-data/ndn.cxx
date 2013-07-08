/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <limits>
#include <stdlib.h>

#include <boost/regex.hpp>

#include "regex-repeat-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{

  bool RegexRepeatMatcher::Compile()
  {
    RegexMatcher* matcher;

    if("(" == m_expr[0])
      matcher = new RegexBackRefMatcher(m_expr.substr(0, m_indicator), m_backRefManager);
    else
      matcher = new RegexComponentSetMatcher(m_expr.substr(0, m_indicator), m_backRefManager);

    m_matcherList.push_back(matcher);
      
    return ParseRepetition();
  }

  bool RegexRepeatMatcher::ParseRepetition()
  {
    string errMsg = "Error: RegexRepeatMatcher.ParseRepetition(): ";
    
    int exprSize = m_epxr.size();
    int intMax = numeric_limits<int>::max();
    
    if(exprSize == m_indicator){
      m_repeatMin = 1;
      m_repeatMax = 1;
      return true;
    }
    else{
      if(exprSize == (m_indicator + 1)){
        if('?' == m_expr[m_indicator]){
          m_repeatMin = 0;
          m_repeatMax = 1;
          return true;
        }
        if('+' == m_expr[m_indicator]){
          m_repeatMin = 1;
          m_repeatMax = intMax;
          return true;
        }
        if('*' == m_expr[m_indicator]){
          m_repeatMin = 0;
          m_repeatMax = intMax;
          return true;
        }
      }
      else{
        string repeatStruct = m_expr.substr(m_indicator, exprSize - m_indicator);
        if(boost::regex_match(repeatStruct, "\{[0-9]+,[0-9]+\}")){
          int separator = repeatStruct.find_first_of(',', 0);

          min = atoi(repeatStruct.substr(1, separator - 1).c_str());
          max = atoi(repeatStruct.substr(separator + 1, exprSize - separator - 1).c_str());

          if(min > intMax || max > intMax || min > max)
            throw RegexException(errMsg + "Wrong number " + m_expr);
          
          m_repeatMin = min;
          m_repeatMax = max;

          return true;
        }
        else
          throw RegexException(errMsg + "Unrecognized format "+ m_expr);
      }
    }
    return false;
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
