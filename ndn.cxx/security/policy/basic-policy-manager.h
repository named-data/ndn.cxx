/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_BASIC_POLICY_MANAGER_H
#define NDN_BASIC_POLICY_MANAGER_H

#include <map>

#include "ndn.cxx/common.h"

#include "policy-manager.h"

#include "ndn.cxx/regex/regex.h"

namespace ndn
{

namespace security
{
  class BasicPolicyManager : public PolicyManager
  {
  public:
    BasicPolicyManager ();

    virtual void 
    setSigningPolicy (const string & policy);

    virtual void 
    setSigningInference(const string & inference);

    virtual void 
    setVerificationPolicy (const string & policy);

    virtual void 
    setTrustAnchor(const Certificate & certificate);

    virtual Ptr<const Certificate>
    getTrustAnchor(const Name & name);

    virtual bool
    requireVerify (const Data & data);

    virtual bool 
    skipVerify (const Data & data);

    virtual bool 
    checkVerificationPolicy(const Data & data);

    virtual bool 
    checkSigningPolicy(const Name & dataName, const Name & certName);

    virtual Name 
    inferSigningCert(const Name & dataName);

  private:
    Ptr<Regex>
    parseInference (const string & inference);
    
    Ptr<Policy>
    parsePolicy (const string & policy);

    string
    getStringItem (const string & policy, int & offset);

    string
    replaceWS (const string & policy);

  private:
    vector< Ptr<Policy> > m_verifyPolicies;
    vector< Ptr<Policy> > m_notVerifyPolicies;
    vector< Ptr<Policy> > m_signPolicies;
    vector< Ptr<Regex> > m_signInference;
    map<Name, Certificate> m_trustAnchors;
  };
}

}

#endif
