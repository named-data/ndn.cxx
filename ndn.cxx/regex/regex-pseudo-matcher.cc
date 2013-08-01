/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-pseudo-matcher.h"

#include "logging.h"

INIT_LOGGER ("RegexPseudoMatcher");

namespace ndn
{

namespace regex
{
  RegexPseudoMatcher::RegexPseudoMatcher()
    :RegexMatcher ("", EXPR_PSEUDO, NULL)
  {}

  void 
  RegexPseudoMatcher::setMatchResult(const string & str)
  {  
    m_matchResult.push_back(name::Component(str));
  }
    
  void 
  RegexPseudoMatcher::resetMatchResult()
  {
    m_matchResult.clear();
  }
}//regex

}//ndn
