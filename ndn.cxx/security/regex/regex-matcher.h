/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_REGEX_MATCHER_H
#define NDN_REGEX_MATCHER_H

#include <string>
#include <vector>

#include <boost/shared_ptr.hpp>

#include "ndn.cxx/fields/name.h"

#include "regex-common.h"
#include "regex-exception.h"
#include "regex-backref-manager.h"

using namespace std;

namespace ndn
{

namespace regex
{
  class RegexMatcher;

  class RegexMatcher
  {
  public:

    enum RegexExprType{
      EXPR_TOP,

      EXPR_PATTERNLIST,

      EXPR_REPEAT_PATTERN,
      
      EXPR_BACKREF,
      EXPR_COMPONENT_SET,
      EXPR_COMPONENT
    };    

    ///////////////////////////////////////////////////////////////////////////////
    //                              CONSTRUCTORS                                 //
    ///////////////////////////////////////////////////////////////////////////////
    RegexMatcher(const string expr, RegexExprType type,  RegexBRManager * backRefManager) 
      : m_expr(expr), 
        m_type(type),
        m_backRefManager(backRefManager)
    {};

    virtual ~RegexMatcher();

    /**
     * @brief Compile the regular expression to generate the more matchers when necessary
     * @returns true if compiling succeeds
     */
    virtual bool Compile() = 0;
    
    /**
     * @brief check if the pattern match the part of name
     * @param name the name against which the pattern is matched
     * @param offset the starting index of matching
     * @param len the number of components to be matched
     * @returns true if match succeeds
     */
    virtual bool Match(Name name, const int & offset, const int & len);
    
    /**
     * @brief get the matched name components
     * @returns the matched name components
     */
    Name GetMatchResult(){return matchResult;}

  protected:
    const string m_expr;
    const RegexExprType m_type; 
    RegexBRManager* m_backRefManager;
    vector<RegexMatcher*> m_matcherList;
    Name matchResult;

  protected:
    int ExtractComponent(int index);

    void PushRef(RegexMatcher* matcher){m_backRefManager->PushRef(matcher);}
    
    void PopRef(RegexMatcher* matcher){m_backRefManager->PopRef();}

  private:
    /**
     * @brief recursively match name components
     * @param mId the index of the matcher in the m_matcherLists
     * @param name the name against which the pattern is matched 
     * @param len the number of components to be matched
     * @return true if matching succeeds
     */
    bool RecursiveMatch(int mId, Name name, const int & offset, const int & len);

  };

}//regex

}//ndn


#endif
