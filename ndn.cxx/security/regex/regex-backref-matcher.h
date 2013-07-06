/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_REGEX_BACKREF_MATCHER_H
#define NDN_REGEX_BACKREF_MATCHER_H

#include "regex-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{

  class RegexBackRefMatcher : public RegexPatternMatcher
  {
  public:
    RegexBackRefMatcher(const string expr, RegexExprType type = EXPR_BACKREF, const in refNum)
      : RegexMatcher (expr, type),
        m_refNum(refNum)
    {}
    
    virtual ~RegexBackRefMatcher();

    virtual bool Compile();
    
  private:
    int m_refNum;
  }
}

}//regex

}//ndn

#endif

