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

INIT_LOGGER ("RegexRepeatMatcher");

using namespace std;

namespace ndn
{

namespace regex
{
  bool RegexComponent::Match(Name name, const int & offset, const int & len)
  {
    _LOG_DEBUG ("offset : " << offset << " len: " << len);
    _LOG_DEBUG ("name : " << name.get(offset).toUri() << " expr: " << m_expr);
    if(0 == len)
      return false;

    if(m_exact == true)
      return boost::regex_match(name.get(offset).toUri(), boost::regex(m_expr));
    else
      return boost::regex_search(name.get(offset).toUri(), boost::regex(m_expr));
  }

} //regex

} //ndn
