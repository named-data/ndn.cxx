/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-component.h"

using namespace std;

namespace ndn
{

namespace regex
{
  RegexComponent::~RegexComponent()
  {
  }

  /**
   * @brief check if the pattern match the part of name
   * @param name name against which the pattern is matched
   * @param offset starting index of matching
   * @param len number of components to be matched
   */
  bool RegexComponent::Match(Name name, const int & offset, const int & len)
  {
    if(m_exact == true)
      return = boost::regex_match(name.get(offset).toUri(), m_expr);
    else
      return boost::regex_search(name.get(offset).toUri(), m_expr);
  }

} //regex

} //ndn
