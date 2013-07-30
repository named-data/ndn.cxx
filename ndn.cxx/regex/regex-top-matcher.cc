/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <stdlib.h>

#include "regex-top-matcher.h"
#include "regex-patternlist-matcher.h"

#include "logging.h"

INIT_LOGGER ("RegexTopMatcher");

using namespace std;

namespace ndn
{

namespace regex
{
  RegexTopMatcher::RegexTopMatcher(const string expr, RegexBRManager *const backRefManager, const string rule)
    : RegexMatcher(expr, EXPR_TOP, backRefManager),
      m_rule(rule)
  {
    m_backRefManager = new RegexBRManager();

    _LOG_DEBUG ("Enter RegexTopMatcher Constructor: " << m_expr);
    if(!compile())
      throw RegexException("RegexTopMatcher Constructor: Cannot compile the regex");
  }

  RegexTopMatcher::~RegexTopMatcher()
  {
    delete m_backRefManager;
  }

  bool RegexTopMatcher::compile()
  {
    _LOG_DEBUG ("Enter RegexTopMatcher::Compile()");

    string errMsg = "Error: RegexTopMatcher.Compile(): ";

    string expr = m_expr;
    if('^' != expr[0])
      expr = "<.*>*" + expr;
    else
      expr = expr.substr(1, expr.size()-1);

    if('$' != expr[expr.size() - 1])
      expr = expr + "<.*>*";
    else
      expr = expr.substr(0, expr.size()-1);

    _LOG_DEBUG ("reconstructed expr: " << expr);

    RegexPatternListMatcher * matcher = new RegexPatternListMatcher(expr, m_backRefManager);
    m_matcherList.push_back(matcher);
    return true;
  }

}//regex

}//ndn
