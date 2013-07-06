/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef REGEX_COMPONENT_SET_MATCHER_H
#define REGEX_COMPONENT_SET_MATCHER_H

#include <set>

#include "regex-matcher.h"


using namespace std;

namespace ndn
{

namespace regex
{
  class RegexComponentSetMatcher : public RegexMatcher
  {

  public:
    RegexComponentSetMatcher(const string expr, RegexExprType type = EXPR_COMPONENT_SET)
      : RegexMatcher(expr, type)
        m_include(true);
    {};
    
    virtual ~RegexComponentSetMatcher();

    virtual bool Compile();

    /**
     * @brief check if the pattern match the part of name
     * @param name name against which the pattern is matched
     * @param offset starting index of matching
     * @param len number of components to be matched
     */    
    virtual bool Match(Name name, const int & offset, const int & len = 1);

  private:
    set<RegexComponent> m_compoents;
    bool m_include;
  }

}//regex

}//ndn

#endif
