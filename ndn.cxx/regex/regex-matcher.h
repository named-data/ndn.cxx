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

#include "ndn.cxx/common.h"
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
      EXPR_COMPONENT,

      EXPR_PSEUDO
    };    

    ///////////////////////////////////////////////////////////////////////////////
    //                              CONSTRUCTORS                                 //
    ///////////////////////////////////////////////////////////////////////////////
    RegexMatcher(const string expr, RegexExprType type,  Ptr<RegexBRManager> backRefManager = NULL) 
      : m_expr(expr), 
        m_type(type),
        m_backRefManager(backRefManager)
    {};

    virtual ~RegexMatcher();

    virtual bool match(const Name & name, const int & offset, const int & len);

    /**
     * @brief get the matched name components
     * @returns the matched name components
     */
    const vector<name::Component> & 
    getMatchResult() const
    {
      return m_matchResult;
    }

    string getExpr(){return m_expr;} 

  protected:
    /**
     * @brief Compile the regular expression to generate the more matchers when necessary
     * @returns true if compiling succeeds
     */
    virtual void compile() = 0;

  private:

    bool recursiveMatch(int mId, Name name, const int & offset, const int & len);

  protected:
    const string m_expr;
    const RegexExprType m_type; 
    Ptr<RegexBRManager> m_backRefManager;
    vector<Ptr<RegexMatcher> > m_matcherList;
    vector<name::Component> m_matchResult;


  };

}//regex

}//ndn


#endif
