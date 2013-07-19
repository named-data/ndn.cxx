/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_REGEX_PATTERNLIST_MATCHER_H
#define NDN_REGEX_PATTERNLIST_MATCHER_H

#include <string>

#include "regex-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{
  class RegexPatternListMatcher : public RegexMatcher
  {
  public:
    RegexPatternListMatcher(const string expr, RegexBRManager* backRefManager);
    
    virtual ~RegexPatternListMatcher(){};

  protected:    
    virtual bool Compile();

  private:
    bool ExtractPattern(int index, int* next);
    
    int ExtractSubPattern(const char left, const char right, int index);
    
    int ExtractRepetition(int index);

  private:

  };

}//regex

}//ndn

#endif
