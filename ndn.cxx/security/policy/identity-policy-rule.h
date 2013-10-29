/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_IDENTITY_POLICY_RULE_H
#define NDN_IDENTITY_POLICY_RULE_H


#include "ndn.cxx/data.h"

#include "ndn.cxx/security/security-common.h"
#include "ndn.cxx/fields/key-locator.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

#include "ndn.cxx/regex/regex.h"

#include "policy-rule.h"

namespace ndn
{

namespace security
{
  
  class IdentityPolicyRule : public PolicyRule
  {
  public:
    IdentityPolicyRule(const string & dataRegex, const string & signerRegex, const string & op, 
                   const string & dataExpand, const string & signerExpand, bool isPositive);

    virtual
    ~IdentityPolicyRule();
    
    virtual bool 
    matchDataName(const Data & data);

    virtual bool 
    matchSignerName(const Data & data);

    virtual bool
    satisfy(const Data & data);

    virtual bool
    satisfy(const Name & dataName, const Name & signerName);

  private:
    bool 
    compare(const Name & dataName, const Name & signerName);

  private:
    const string m_dataRegex;
    const string m_signerRegex;
    const string m_op;
    const string m_dataExpand;
    const string m_signerExpand;

    Regex m_dataNameRegex;
    Regex m_signerNameRegex;
  };

}//security

}//ndn

#endif
