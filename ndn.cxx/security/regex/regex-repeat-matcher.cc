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
#include "regex-backref-matcher.h"
#include "regex-componentset-matcher.h"

#include "logging.h"

INIT_LOGGER ("RegexRepeatMatcher");

using namespace std;

namespace ndn
{

namespace regex
{
  RegexRepeatMatcher::RegexRepeatMatcher(const string expr, RegexBRManager* backRefManager, int indicator)
    : RegexMatcher (expr, EXPR_REPEAT_PATTERN, backRefManager),
      m_indicator(indicator)
  {
    _LOG_DEBUG ("Enter RegexRepeatMatcher Constructor");
    if(!Compile())
      throw RegexException("RegexRepeatMatcher Constructor: Cannot compile the regex");
  }

  bool RegexRepeatMatcher::Compile()
  {
    _LOG_DEBUG ("Enter RegexRepeatMatcher::Compile()");
    
    RegexMatcher* matcher;

    if('(' == m_expr[0]){
      matcher = (RegexMatcher*) new RegexBackRefMatcher(m_expr.substr(0, m_indicator), m_backRefManager);
    }
    else{
      matcher = (RegexMatcher*) new RegexComponentSetMatcher(m_expr.substr(0, m_indicator), m_backRefManager);
    }
    m_matcherList.push_back(matcher);
      
    return ParseRepetition();
  }

  bool RegexRepeatMatcher::ParseRepetition()
  {
    _LOG_DEBUG ("Enter RegexRepeatMatcher::ParseRepetition()");

    string errMsg = "Error: RegexRepeatMatcher.ParseRepetition(): ";
    
    int exprSize = m_expr.size();
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
        int min = 0;
        int max = 0;

        if(boost::regex_match(repeatStruct, boost::regex("{\\{[0-9]+,[0-9]+\\}"))){
          int separator = repeatStruct.find_first_of(',', 0);

          min = atoi(repeatStruct.substr(1, separator - 1).c_str());
          max = atoi(repeatStruct.substr(separator + 1, exprSize - separator - 1).c_str());
        }
        else if(boost::regex_match(repeatStruct, boost::regex("{\\{[0-9]+\\}"))){
          min = atoi(repeatStruct.substr(1, exprSize - 1).c_str());
          max = min;
        }
        else
          throw RegexException(errMsg + "Unrecognized format "+ m_expr);
        
        if(min > intMax || max > intMax || min > max)
            throw RegexException(errMsg + "Wrong number " + m_expr);
          
        m_repeatMin = min;
        m_repeatMax = max;
        
        return true;
      }
    }
    return false;
  }



  bool RegexRepeatMatcher::Match(Name name, const int & offset, const int & len)
  {

    _LOG_DEBUG ("Enter RegexRepeatMatcher::Match()");
    _LOG_DEBUG ("expr: " << m_expr << " min: " << m_repeatMin << " max: " << m_repeatMax);   

    /* for no repeat case */
    if(0 == m_repeatMin)
      if(0 == len)
        return true;

    /* for repeatMin > 1 */
    return RecursiveMatch(m_matcherList[0], 0, name, offset, len);
  }
  
  bool RegexRepeatMatcher::RecursiveMatch(RegexMatcher* matcher, 
					  int repeat, 
					  Name name, 
					  const int & offset, 
					  const int &len)
  {
    _LOG_DEBUG ("Enter RegexRepeatMatcher::RecursiveMatch()");
    _LOG_DEBUG ("repeat: " << repeat << " name: " << name << " offset: " << offset << " len: " << len);
    _LOG_DEBUG ("min: " << m_repeatMin << " max: " << m_repeatMax);
    int tried = 0;


    /* if max repeat has been reached, but we still have more to match, matching fails */
    if(0 < len && repeat > m_repeatMax){
      _LOG_DEBUG ("Match Fail: Reach m_repeatMax && More components");
      return false;
    }
    
    /* if all components have been matched, but we haven't reach the min repeat, matching fails */
    if(0 == len && repeat < m_repeatMin){
      _LOG_DEBUG ("Match Fail: No more components && have NOT reached m_repeatMin");
      return false;
    }

    /* if all components have been matched and repeat has been more than min, match succeeds */
    if(0 == len && repeat >= m_repeatMin){
      _LOG_DEBUG ("Match Succeed: No more components && reach m_repeatMin");
      return true;
    }    

    while(tried <= len){
      _LOG_DEBUG ("Attempt tried: " << tried);
      if(matcher->Match(name, offset, tried) && RecursiveMatch(matcher, repeat + 1, name, offset + tried, len - tried))
        return true;
      _LOG_DEBUG ("Failed at tried: " << tried);
      tried++;
    }

    return false;
  }

}//regex

}//ndn
