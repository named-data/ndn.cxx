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

#inclue "regex-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{
  class RegexRepeatMatcher : public RegexMatcher
  {
  public:
    RegexRepeatMatcher(const string expr, RegexExprType type = EXPR_REPEAT_PATTERN)
      : RegexMatcher (expr, type)
    {};
    
    virtual ~RegexRepeatMatcher();

    virtual bool Compile();

    virtual bool Match(Name name, const int & offset, const int & len);

  private:
    bool RecursiveMatch(RegexMatcher* matcher,
                        int repeat,
                        Name, name,
                        const int & offset,
                        const int &len);

    int m_repeatMin;
    int m_repeatMax;
  };

}//regex

}//ndn

#endif
