/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-componentset-matcher.h"

using namespace std;

namespace ndn
{

namespace regex
{
  bool RegexComponentSetMatcher::Compile()
  {
    //TODO
  }

  /**
   * @brief check if the pattern match the part of name
   * @param name name against which the pattern is matched
   * @param offset starting index of matching
   * @param len number of components to be matched
   */
  bool RegexComponentSetMatcher::Match(Name name, const int & offset, const int & len)
  {
    bool matched = false;

    set<RegexComponent>::iterator it = m_components.begin();

    for(; it != m_components.end(); it++){
      if(it->Match(name, offset, index)){
        matched = true;
        break;
      }
    }
    return (m_include ? matched : !matched);
  }

}//regex

}//ndn
