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

#include <string>

#include "regex-matcher.h"
#include "regex-patternlist-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{
  class RegexTopMatcher: public RegexMatcher
  {
  public:
    RegexTopMatcher(const string & expr, Ptr<RegexBRManager> backRefManager = NULL);
    
    virtual ~RegexTopMatcher();

    bool 
    match(const Name & name);

    virtual bool
    match (const Name & name, const int & offset, const int & len);

    virtual Name 
    expand (const string & expand);

  protected:
    virtual void 
    compile();

  private:
    string
    getItemFromExpand(const string & expand, int & offset);

  private:
    Ptr<RegexPatternListMatcher> m_primaryMatcher;
    Ptr<RegexPatternListMatcher> m_secondaryMatcher;
    Ptr<RegexBRManager> m_primaryBackRefManager;
    Ptr<RegexBRManager> m_secondaryBackRefManager;
    bool m_secondaryUsed;
  };
  typedef RegexTopMatcher Regex;
}

}

#endif
