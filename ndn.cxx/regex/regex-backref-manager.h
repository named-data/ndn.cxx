/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_REGEX_BRMANAGER_H
#define NDN_REGEX_BRMANAGER_H

#include <vector>
#include "ndn.cxx/common.h"

using namespace std;

namespace ndn
{

namespace regex
{

  class RegexMatcher;

  class RegexBRManager
  {
  public:
    RegexBRManager(){}
    
    virtual ~RegexBRManager();
    
    virtual int 
    pushRef(Ptr<RegexMatcher> matcher);
    
    virtual int 
    popRef();

    virtual int 
    getNum(){return m_backRefs.size();}
    
    virtual Ptr<RegexMatcher> 
    getBackRef(int i){return m_backRefs[i];}
    
  private:
    vector<Ptr<RegexMatcher> > m_backRefs;
  };

}//regex

}//ndn

#endif
