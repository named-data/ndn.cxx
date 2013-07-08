/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_REGEX_MATCHER_H
#define NDN_REGEX_MATCHER_H

#include <vector>

#include "ndn.cxx/fields/name.h"

using namespace std;

namespace ndn
{

namespace regex
{

  class RegexMatcher
  {
  public:

    enum RegexExprType{
      EXPR_TOP,

      EXPR_HEAD,
      EXPR_TAIL,
      EXPR_HEAD_TAIL,      
      EXPR_PATTERN,

      EXPR_REPEAT_PATTERN,
      EXPR_SUBPATTERN,
      
      EXPR_BACKREF,
      EXPR_COMPONENT_SET,
      EXPR_COMPONENT
    };    

    ///////////////////////////////////////////////////////////////////////////////
    //                              CONSTRUCTORS                                 //
    ///////////////////////////////////////////////////////////////////////////////
    RegexMatcher(const string expr, RegexExprType type,  RegexBRManager *const backRefManager) 
      : m_expr(expr), 
        m_type(type),
        m_backRefManager(backRefManager)
    {};

    virtual ~RegexMatcher();

    virtual bool Compile();
    
    /**
     * @brief check if the pattern match the whole component
     * @param name name against which the pattern is matched
     * @param index index of the next component to be matched
     */
    virtual bool Match(Name name, const int & offset, const int & len) = 0;

  private:
    int ExtractSubPattern(int index);

    int ExtractBackRef(int index);
    
    int ExtractComponent(int index);
    
    int ExtractRepetition (int index);

    int CheckDollar(int index);
    
    RegexExprType GetRegexExprType(string expr);

  private:
    const string m_expr;
    const int m_offset;
    RegexBRManager *const m_backRefManager;
    const RegexExprType m_type; 
    vector<RegexMatcher*> m_matcherList;
  };

}//regex

}//ndn


#endif
