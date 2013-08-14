/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <boost/regex.hpp>

#include "regex-backref-matcher.h"
#include "regex-patternlist-matcher.h"

#include "logging.h"

INIT_LOGGER ("RegexBackRefMatcher");

using namespace std;

namespace ndn
{

namespace regex
{
  RegexBackRefMatcher::RegexBackRefMatcher(const string expr, Ptr<RegexBRManager> backRefManager)
    : RegexMatcher (expr, EXPR_BACKREF, backRefManager)
  {
    // _LOG_TRACE ("Enter RegexBackRefMatcher Constructor: ");
    // compile();
    // _LOG_TRACE ("Exit RegexBackRefMatcher Constructor: ");
  }

  void 
  RegexBackRefMatcher::compile()
  {
    // _LOG_TRACE ("Enter RegexBackRefMatcher::compile()");

    string errMsg = "Error: RegexBackRefMatcher.Compile(): ";
    
    // _LOG_DEBUG ("m_backRefManager: " << m_backRefManager);

    int lastIndex = m_expr.size() - 1;
    if('(' == m_expr[0] && ')' == m_expr[lastIndex]){
      // m_backRefManager->pushRef(this);

      Ptr<RegexMatcher> matcher = Ptr<RegexMatcher>(new RegexPatternListMatcher(m_expr.substr(1, lastIndex - 1), m_backRefManager));
      m_matcherList.push_back(matcher);
      
    }
    else
      throw RegexException(errMsg + " Unrecognoized format " + m_expr);
    
    // _LOG_TRACE ("Exit RegexBackRefMatcher::compile");
  }

}//regex

}//ndn



