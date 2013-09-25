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
#include <tinyxml.h>

#include "ndn.cxx/common.h"

#include "policy-manager.h"

#include "ndn.cxx/regex/regex.h"
#include "ndn.cxx/security/identity/privatekey-storage.h"
#include "ndn.cxx/security/cache/certificate-cache.h"

namespace ndn
{

namespace security
{
  class BasicPolicyManager : public PolicyManager
  {
  public:
    BasicPolicyManager (const string & policyPath, 
                        Ptr<PrivatekeyStorage> privatekeyStore, 
                        Ptr<CertificateCache> certificateCache,
                        const int & stepLimit);

    virtual
    ~BasicPolicyManager();
    
    virtual void
    loadPolicy();

    void 
    loadPolicySet(TiXmlElement * element);

    void 
    loadTrustAnchor(TiXmlElement * element);

    virtual void 
    setDefaultEncryptionKey(const Name & keyName, bool sym);
    
    virtual void
    savePolicy(const Name & keyName = Name(), bool sym = true);

    virtual void 
    setSigningPolicyRule (Ptr<PolicyRule> policy);

    virtual void 
    setSigningInference(Ptr<Regex> inference);

    virtual void
    setVerificationPolicyRule (Ptr<PolicyRule> policy);

    virtual void
    setVerificationExemption(Ptr<Regex> exempt);

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

    virtual Ptr<ValidationRequest>
    checkVerificationPolicy(Ptr<Data> data, 
                            const int & stepCount, 
                            const DataCallback& verifiedCallback,
                            const UnverifiedCallback& unverifiedCallback);

    virtual bool 
    checkSigningPolicy(const Name & dataName, const Name & certName);

    virtual Name 
    inferSigningIdentity(const Name & dataName);

    void
    displayPolicy ();

  private:
    virtual void
    onCertificateVerified(Ptr<Data> certificate, 
                          Ptr<Data> data, 
                          const DataCallback& verifiedCallback, 
                          const UnverifiedCallback& unverifiedCallback);

    virtual void
    onCertificateUnverified(Ptr<Data>signCertificate, 
                            Ptr<Data>data, 
                            const UnverifiedCallback &unverifiedCallback);

    Ptr<Regex>
    parseInference (const string & inference);
    
    Ptr<PolicyRule>
    parsePolicyRule (const string & policy);

    string
    getStringItem (const string & policy, int & offset);

    string
    replaceWS (const string & policy);

    TiXmlDocument * toXML ();
    
    virtual void
    loadPolicyFromFile();

  private:
    const string m_policyPath;
    bool m_policyChanged;
    bool m_policyLoaded;
    Ptr<PrivatekeyStorage> m_privatekeyStore;
    vector< Ptr<PolicyRule> > m_mustFailVerify;
    vector< Ptr<PolicyRule> > m_verifyPolicies;
    vector< Ptr<Regex> > m_verifyExempt;
    vector< Ptr<PolicyRule> > m_signPolicies;
    vector< Ptr<PolicyRule> > m_mustFailSign;
    vector< Ptr<Regex> > m_signInference;
    map<Name, Certificate> m_trustAnchors;
    
    int m_stepLimit;
    Ptr<CertificateCache> m_certificateCache;
  };
}

}

#endif
