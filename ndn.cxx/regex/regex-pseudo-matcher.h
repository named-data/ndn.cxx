/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_REGEX_PSEUDO_MATCHER_H
#define NDN_REGEX_PSEUDO_MATCHER_H

#include "regex-matcher.h"
#include <string>

using namespace std;

namespace ndn
{

namespace regex
{
  class RegexPseudoMatcher : public RegexMatcher
  {
  public:
    RegexPseudoMatcher();

    ~RegexPseudoMatcher() {};

    virtual void 
    compile() 
    {}

    void 
    setMatchResult(const string & str);

    void 
    resetMatchResult();

  private:
    
  };

}//regex

}//ndn

#endif
