/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_SIMPLE_POLICY_MANAGER_H
#define NDN_SIMPLE_POLICY_MANAGER_H

#include <map>

#include "policy-manager.h"

#include "ndn.cxx/regex/regex.h"
#include "ndn.cxx/security/certificate/identity-certificate.h"
#include "ndn.cxx/security/cache/certificate-cache.h"

namespace ndn
{

namespace security
{
  class SimplePolicyManager : public PolicyManager
  {
  public:
    typedef vector< Ptr<PolicyRule> > RuleList;
    typedef vector< Ptr<Regex> > RegexList;

  public:
    SimplePolicyManager(const int & stepLimit,
                        Ptr<CertificateCache> certificateCache);

    virtual 
    ~SimplePolicyManager() {}

    /**
     * @brief check if the received data packet can escape from verification
     * @param data the received data packet
     * @return true if the data does not need to be verified, otherwise false
     */
    virtual bool 
    skipVerifyAndTrust (const Data & data);

    /**
     * @brief check if PolicyManager has the verification rule for the received data
     * @param data the received data packet
     * @return true if the data must be verified, otherwise false
     */
    virtual bool
    requireVerify (const Data & data);

    /**
     * @brief check whether received data packet complies with the verification policy, and get the indication of next verification step
     * @param data the received data packet
     * @param stepCount the number of verification steps that have been done, used to track the verification progress
     * @param verifiedCallback the callback function that will be called if the received data packet has been validated
     * @param unverifiedCallback the callback function that will be called if the received data packet cannot be validated
     * @return the indication of next verification step, NULL if there is no further step
     */
    virtual Ptr<ValidationRequest>
    checkVerificationPolicy(Ptr<Data> data, 
                            const int & stepCount, 
                            const DataCallback& verifiedCallback,
                            const UnverifiedCallback& unverifiedCallback);

    
    /**
     * @brief check if the signing certificate name and data name satify the signing policy 
     * @param dataName the name of data to be signed
     * @param certificateName the name of signing certificate
     * @return true if the signing certificate can be used to sign the data, otherwise false
     */
    virtual bool 
    checkSigningPolicy(const Name & dataName, const Name & certificateName);
    
    /**
     * @brief Infer signing identity name according to policy, if the signing identity cannot be inferred, it should return empty name
     * @param dataName, the name of data to be signed
     * @return the signing identity. 
     */
    virtual Name 
    inferSigningIdentity(const Name & dataName);

    /**
     * @brief add a rule to check whether a signing certificate is allowed to sign a data 
     * @param policy the signing policy
     */
    inline virtual void 
    addSigningPolicyRule (Ptr<PolicyRule> policy);

    /**
     * @brief add a rule to infer the signing identity for a data packet
     * @param inference the signing inference
     */
    inline virtual void 
    addSigningInference(Ptr<Regex> inference);

    /**
     * @brief add a rule to check whether the data name and signing certificate name comply with the policy
     * @param policy the verification policy
     */
    inline virtual void
    addVerificationPolicyRule (Ptr<PolicyRule> policy);

    /**
     * @brief add a rule to exempt a data packet from verification 
     * @param exempt the exemption rule
     */
    inline virtual void
    addVerificationExemption(Ptr<Regex> exempt);

    /**
     * @brief add a trust anchor
     * @param certificate the trust anchor 
     */
    inline virtual void 
    addTrustAnchor(Ptr<IdentityCertificate> certificate);

  protected:
    virtual void
    onCertificateVerified(Ptr<Data> certificate, 
                          Ptr<Data> data, 
                          const DataCallback& verifiedCallback, 
                          const UnverifiedCallback& unverifiedCallback);

    virtual void
    onCertificateUnverified(Ptr<Data>signCertificate, 
                            Ptr<Data>data, 
                            const UnverifiedCallback &unverifiedCallback);
    
  protected:
    int m_stepLimit;
    Ptr<CertificateCache> m_certificateCache;
    RuleList m_mustFailVerify;
    RuleList m_verifyPolicies;
    RegexList m_verifyExempt;
    RuleList m_signPolicies;
    RuleList m_mustFailSign;
    RegexList m_signInference;
    std::map<Name, Ptr<IdentityCertificate> > m_trustAnchors;    
  };

  inline void 
  SimplePolicyManager::addSigningPolicyRule (Ptr<PolicyRule> policy)
  { policy->isPositive() ? m_signPolicies.push_back(policy) : m_mustFailSign.push_back(policy); }

  inline void
  SimplePolicyManager::addSigningInference (Ptr<Regex> inference)
  { m_signInference.push_back(inference); }

  inline void 
  SimplePolicyManager::addVerificationPolicyRule (Ptr<PolicyRule> policy)
  { policy->isPositive() ? m_verifyPolicies.push_back(policy) : m_mustFailVerify.push_back(policy); }
      
  inline void 
  SimplePolicyManager::addVerificationExemption (Ptr<Regex> exempt)
  { m_verifyExempt.push_back(exempt); }

  inline void  
  SimplePolicyManager::addTrustAnchor(Ptr<IdentityCertificate> certificate)
  { m_trustAnchors.insert(pair<Name, Ptr<IdentityCertificate> >(certificate->getName(), certificate)); }

}//security

}//ndn

#endif
