/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_REGEX_REPEAT_MATCHER_H
#define NDN_REGEX_REPEAT_MATCHER_H

#include "regex-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{
  class RegexRepeatMatcher : public RegexMatcher
  {
  public:
    RegexRepeatMatcher(const string expr, Ptr<RegexBRManager> backRefManager, int indicator);
    
    virtual ~RegexRepeatMatcher(){}

    virtual bool 
    match(const Name & name, const int & offset, const int & len);

  protected:
    /**
     * @brief Compile the regular expression to generate the more matchers when necessary
     * @returns true if compiling succeeds
     */
    virtual void 
    compile();


  private:
    bool 
    parseRepetition();

    bool 
    recursiveMatch (int repeat,
                    const Name & name,
                    const int & offset,
                    const int &len);
  
  private:
    int m_indicator;
    int m_repeatMin;
    int m_repeatMax;
  };

}//regex

}//ndn

#endif
