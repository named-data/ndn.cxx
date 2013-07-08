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

using namespace std;

namespace ndn
{

namespace regex
{
  class RegexPatternListMatcher : public RegexMatcher
  {
  public:
    RegexPatternListMatcher(const string expr, RegexBRManager* backRefManager)
      :RegexMatcher(expr, EXPR_PATTERNLIST, backRefManager)
    {};
    
    virtual ~RegexPatternListMatcher(){};
    
    virtual bool Compile();
    
    virtual bool Match(Name name, const int & offset, const int & len = 1);

  private:
    bool ExtractPattern(int index, int* next);
    
    int ExtractSubPattern(const char left, const char rightint index);

  }
}//regex

}//ndn

#endif
