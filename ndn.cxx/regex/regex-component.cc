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

#include "logging.h"

INIT_LOGGER ("RegexComponent");

using namespace std;

namespace ndn
{

namespace regex
{
  RegexComponent::RegexComponent(const string expr, RegexBRManager * const backRefManager, bool exact)
    : RegexMatcher (expr, EXPR_COMPONENT, backRefManager),
      m_exact(exact)
  {
    _LOG_DEBUG ("Enter RegexComponent Constructor: " << m_expr);
    if(!Compile())
      throw RegexException("RegexComponent Constructor: Cannot compile the regex");
  }

  bool RegexComponent::Match(Name name, const int & offset, const int & len)
  {
    _LOG_DEBUG ("Enter RegexComponent::Match: ");
    _LOG_DEBUG ("name : "<< name << " offset : " << offset << " len: " << len);

    m_matchResult = Name();

    if(0 == len)
      return false;

    if(m_exact == true){
      if(boost::regex_match(name.get(offset).toUri(), boost::regex(m_expr))){
        m_matchResult.append(name.get(offset));
        return true;
      }
      else
        return false;
    }
    else{
      if(boost::regex_search(name.get(offset).toUri(), boost::regex(m_expr))){
        m_matchResult.append(name.get(offset));
        return true;
      }
      else
        return false;
    }
  }


} //regex

} //ndn
