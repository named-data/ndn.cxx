/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef REGEX_COMPONENT_SET_MATCHER_H
#define REGEX_COMPONENT_SET_MATCHER_H

#include <set>

#include "regex-matcher.h"
#include "regex-component.h"

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
    RegexComponentSetMatcher(const string expr, RegexBRManager *const backRefManager, bool include = true);    
    virtual ~RegexComponentSetMatcher();

    /**
     * @brief check if the pattern match the part of name
     * @param name name against which the pattern is matched
     * @param offset starting index of matching
     * @param len number of components to be matched
     */    
    virtual bool cMatch(Name name, const int & offset, const int & len = 1);

  protected:    
    /**
     * @brief Compile the regular expression to generate the more matchers when necessary
     * @returns true if compiling succeeds
     */
    virtual bool compile();

  private:
    int extractComponent(int index);

    bool compileSingleComponent();
    
    bool compileMultipleComponents(const int start, const int lastIndex);

  private:
    set<RegexComponent*> m_components;
    bool m_include;
  };

}//regex

}//ndn

#endif
