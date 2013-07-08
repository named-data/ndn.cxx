/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-backref-manager.h"

namespace ndn
{

namespace regex
{
  int RegexBRManager::PushRef(RegexMatcher* matcher)
  {
    int last = m_backRefs.size();
    m_backRefs.push_back(matcher);

    return last;
  }

  int RegexBRManager::PopRef()
  {
    m_backRefs.pop_back();
    
    return m_backRefs.size();
  }
}

}//ndn
