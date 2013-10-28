/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_POLICY_RULE_H
#define NDN_POLICY_RULE_H

#include "ndn.cxx/data.h"

#include <tinyxml.h>

namespace ndn
{

namespace security
{

  class PolicyRule
  {
  public:

    enum PolicyType{
      IDENTITY_POLICY,
    };

    PolicyRule(PolicyType policyType, bool isPositive)
      :m_type(policyType),
       m_isPositive(isPositive)
    {}

    virtual 
    ~PolicyRule() 
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
    isPositive()
    {
      return m_isPositive;
    }
    
  protected:
    PolicyType m_type;
    bool m_isPositive;
  };

}//security

}//ndn

#endif
