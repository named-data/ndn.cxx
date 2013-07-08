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
    ///////////////////////////////////////////////////////////////////////////////
    //                              CONSTRUCTORS                                 //
    ///////////////////////////////////////////////////////////////////////////////

    /**
     * @brief Create a RegexComponentSetMatcher matcher from expr
     * @param expr The standard regular expression to match a component
     * @param exact The flag to provide exact match
     * @param backRefNum The starting back reference number
     */
    RegexComponentSetMatcher(const string expr, RegexBRManager *const backRefManager)
      : RegexMatcher(expr, EXPR_COMPONENT_SET, backRefManager)
        m_include(true);
    {};
    
    virtual ~RegexComponentSetMatcher();
    
    /**
     * @brief Compile the regular expression to generate the more matchers when necessary
     * @returns true if compiling succeeds
     */
    virtual bool Compile();

    /**
     * @brief check if the pattern match the part of name
     * @param name name against which the pattern is matched
     * @param offset starting index of matching
     * @param len number of components to be matched
     */    
    virtual bool Match(Name name, const int & offset, const int & len = 1);

  private:
    bool CompileSingleComponent();
    
    bool CompileMultipleComponents(const int start, const int lastIndex);

  private:
    set<RegexComponent*> m_compoents;
    bool m_include;
  }

}//regex

}//ndn

#endif
