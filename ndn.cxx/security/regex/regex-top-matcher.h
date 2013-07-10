/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_REGEX_TOP_MATCHER_H
#define NDN_REGEX_TOP_MATCHER_H

#include <string>

#include "regex-matcher.h"
#include "regex-patternlist-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{
  class RegexTopMatcher: public RegexMatcher
  {
  public:

    enum RegexTgtCmptType{
      TCT_REFERENCE,
      TCT_COMPONENT,
      TCT_END
    };

  public:
    RegexTopMatcher(const string expr, RegexBRManager *const backRefManager = NULL, const string rule = "");
    
    virtual ~RegexTopMatcher();

    virtual bool MatchName(Name name);

    virtual bool MatchRule(Name name, Name target);

  protected:
    virtual bool Compile();

  private:
    virtual RegexTgtCmptType ParseRule(int index, int * end);

  private:
    string m_rule;
    
  };
}

}

#endif
