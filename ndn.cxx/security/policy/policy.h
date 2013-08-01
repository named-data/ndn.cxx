/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_POLICY_H
#define NDN_POLICY_H

#include "ndn.cxx/data.h"

namespace ndn
{

namespace security
{

  class Policy
  {
    enum PolicyType{
      IDENTITY_POLICY,
    };

  public:
    virtual bool match(const Data & data) = 0;
    
  private:
    PolicyType m_type;
  };

}//security

}//ndn

#endif
