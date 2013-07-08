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

using namespace std;

namespace ndn
{

namespace regex
{
  bool RegexBackRefMatcher::Compile()
  {
    string errMsg = "Error: RegexBackRefMatcher.Compile(): ";

    int lastIndex = m_expr.size() - 1;
    if('(' == m_expr[0] && ')' == m_expr[lastIndex]){
      PushRef(this);

      RegexMatcher* matcher = new RegexPatternListMatcher(m_expr.substr(1, lastIndex - 1), m_backRefManager);
      m_matcherList.push_back(matcher);
      return matcher->Compile();
    }
    else
      throw RegexException(errMsg + " Unrecognoized format " + m_expr);
  }

}//regex

}//ndn



