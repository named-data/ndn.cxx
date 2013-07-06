/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_REGEX_COMPONENT_H
#define NDN_REGEX_COMPONENT_H

#include <string>
#include <boost/regex.hpp>

#include "ndn.cxx/fields/name.h"

#include "regex-parser.h"


using namespace std;


namespace ndn
{

namespace regex
{
    
  class RegexComponent : public RegexMatcher
  {
  public:
    RegexComponent(const string expr, RegexExprType type = EXPR_COMPONENT, bool exact = true) 
      : RegexMatcher (expr, type),
        m_exact(exact)
    {};
    
    virtual ~RegexComponent();

    /**
     * @brief check if the pattern match the part of name
     * @param name name against which the pattern is matched
     * @param offset starting index of matching
     * @param len number of components to be matched
     */
    virtual bool Match(Name name, const int & offset, const int & len = 1);
    
  private:
    bool m_exact;
  };

}//regex
    
}//ndn

#endif
