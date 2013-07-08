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

#include "regex-top-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{
  bool RegexTopMatcher::Compile()
  {
    string expr = m_expr;
    if('^' != m_expr[0])
      expr = "[.*]*" + expr;
    if('$' != m_expr[m_expr.size() - 1])
      expr = expr + "[.*]*";
    
    RegexMatcher * matcher = new RegexPatternListMatcher(expr, EXPR_PATTERNLIST, m_backRefManager);
    if(macher->Compile()){
      m_matcherList->push_back(matcher);
      return true;
    }
    else
      throw RegexException(errMsg + " Cannot compile");

    return false;
  }

  bool RegexTopMatcher::Match(Name name, const int & offset, const int & len)
  {
  }
}//regex

}//ndn

#endif 
