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

#include <tinyxml.h>

namespace ndn
{

namespace security
{

  class Policy
  {
  public:

    enum PolicyType{
      IDENTITY_POLICY,
    };

    Policy(PolicyType policyType, bool mustVerify)
      :m_type(policyType),
       m_mustVerify(mustVerify)
    {}

    virtual 
    ~Policy() 
    {}

    virtual bool 
    matchDataName(const Data & data) = 0;

    virtual bool 
    matchSignerName(const Data & data) = 0;

    virtual bool
    satisfy(const Data & data) = 0;

    virtual bool
    satisfy(const Name & dataName, const Name & signerName) = 0;

    virtual TiXmlElement *
    toXmlElement() = 0;

    PolicyType 
    policyType()
    {
      return m_type;
    }

    bool
    mustVerify()
    {
      return m_mustVerify;
    }
    
  private:
    const PolicyType m_type;
    const bool m_mustVerify;
  };

}//security

}//ndn

#endif
