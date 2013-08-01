/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_REGEX_BACKREF_MATCHER_H
#define NDN_REGEX_BACKREF_MATCHER_H

#include "regex-matcher.h"

#include <boost/enable_shared_from_this.hpp>

using namespace std;

namespace ndn
{

namespace regex
{

  class RegexBackRefMatcher : public RegexMatcher
  {
  public:
    RegexBackRefMatcher(const string expr, Ptr<RegexBRManager> backRefManager);
    
    virtual ~RegexBackRefMatcher(){}

    void 
    lateCompile()
    {
      compile();
    }

  protected:
    virtual void 
    compile();
    
  private:
    int m_refNum;
  };

}//regex

}//ndn

#endif

