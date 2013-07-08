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
    RegexRepeatMatcher(const string expr, RegexBRManager* backRefManager, int indicator)
      : RegexMatcher (expr, EXPR_REPEAT_PATTERN, backRefManager),
        m_indicator(indicator)
    {}
    
    virtual ~RegexRepeatMatcher(){}

    /**
     * @brief Compile the regular expression to generate the more matchers when necessary
     * @returns true if compiling succeeds
     */
    virtual bool Compile();

    /**
     * @brief check if the pattern match the part of name
     * @param name name against which the pattern is matched
     * @param offset starting index of matching
     * @param len number of components to be matched
     */
    virtual bool Match(Name name, const int & offset, const int & len);

  private:
    bool ParseRepetition();

    bool RecursiveMatch(RegexMatcher* matcher,
                        int repeat,
                        Name name,
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
