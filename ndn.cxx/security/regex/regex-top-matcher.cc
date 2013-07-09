/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-top-matcher.h"
#include "regex-patternlist-matcher.h"

#include "logging.h"

INIT_LOGGER ("RegexTopMatcher");

using namespace std;

namespace ndn
{

namespace regex
{
  RegexTopMatcher::RegexTopMatcher(const string expr, RegexBRManager *const backRefManager)
    : RegexMatcher(expr, EXPR_TOP, backRefManager)
  {
    _LOG_DEBUG ("Enter RegexTopMatcher Constructor");
    if(!Compile())
      throw RegexException("RegexTopMatcher Constructor: Cannot compile the regex");
  }

  bool RegexTopMatcher::Compile()
  {
    _LOG_DEBUG ("Enter RegexTopMatcher::Compile()");

    string errMsg = "Error: RegexTopMatcher.Compile(): ";

    string expr = m_expr;
    if('^' != m_expr[0])
      expr = "<.*>*" + expr;
    if('$' != m_expr[m_expr.size() - 1])
      expr = expr + "<.*>*";
    
    RegexPatternListMatcher * matcher = new RegexPatternListMatcher(expr, m_backRefManager);
    m_matcherList.push_back(matcher);
    return true;
  }

}//regex

}//ndn
