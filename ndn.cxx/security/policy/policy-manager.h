/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_POLICY_MANAGER_H
#define NDN_POLICY_MANAGER_H

#include <string>

#include "ndn.cxx/data.h"
#include "ndn.cxx/fields/name.h"
#include "ndn.cxx/regex/regex.h"

#include "ndn.cxx/security/certificate/certificate.h"

#include "policy-rule.h"



using namespace std;


namespace ndn
{

namespace security
{
  class PolicyManager
  {
  public:
    PolicyManager() {}
    
    virtual
    ~PolicyManager() {}

    virtual void
    loadPolicy() = 0;

    virtual void 
    setDefaultEncryptionKey(const string & keyName, bool sym) = 0;

    virtual void
    savePolicy(const string & keyName = "", bool sym = true) = 0;

    // virtual void 
    // setSigningPolicyRule(const string & policy) = 0;

    virtual void 
    setSigningPolicyRule(Ptr<PolicyRule> policy) = 0;

    // virtual void 
    // setSigningInference(const string & inference) = 0;

    virtual void 
    setSigningInference(Ptr<Regex> inference) = 0;

    // virtual void 
    // setVerificationPolicyRule(const string & policy) = 0;

    virtual void 
    setVerificationPolicyRule(Ptr<PolicyRule> policy) = 0;

    virtual void
    setVerificationExemption(Ptr<Regex> exempt) = 0;

    virtual void 
    setTrustAnchor(const Certificate & certificate) = 0;

    virtual bool 
    skipVerify (const Data & data) = 0;

    virtual bool
    requireVerify (const Data & data) = 0;

    virtual Ptr<const Certificate>
    getTrustAnchor(const Name & anchorName) = 0;

    virtual bool 
    checkVerificationPolicy(const Data & data) = 0;
    
    virtual bool 
    checkSigningPolicy(const Name & dataName, const Name & certName) = 0;
    
    virtual Name 
    inferSigningIdentity(const Name & dataName) = 0;

    virtual void
    displayPolicy () = 0;

  protected:
    string m_defaultKeyName;
    bool m_defaultSym;
  };

}//security

}//ndn

#endif
