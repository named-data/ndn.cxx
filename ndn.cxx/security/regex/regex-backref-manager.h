/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_REGEX_BACKREF_MANAGER_H
#define NDN_REGEX_BACKREF_MANAGER_H

namespace ndn
{

namespace regex
{
  class RegexBRManager
  {
  public:
    RegexBRManager();
    
    virtual ~RegexBRManager();
    
    virtual int PushRef(RegexBackRefMatcher* matcher);
    
    virtual int PopRef();
    
    virtual RegexBackRefMatcher* getBackRef(int i){return m_backRefs[i];}
    
  private:
    vector<RegexBackRefMatcher*> m_backRefs;
  }

}//regex

}//ndn

#endif
