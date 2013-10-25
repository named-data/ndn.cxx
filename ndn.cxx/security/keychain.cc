/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */
#include "config.h"
#include "keychain.h"

#include "ndn.cxx/wrapper/wrapper.h"
#include "ndn.cxx/wire/ndnb.h"
#include "ndn.cxx/fields/key-locator.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

#include "exception.h"

#ifdef USE_SIMPLE_POLICY_MANAGER
#include "policy/simple-policy-manager.h"
#include "policy/identity-policy-rule.h"
#endif

#ifdef USE_NO_VERIFY_POLICY_MANAGER
#include "policy/no-verify-policy-manager.h"
#endif

#ifdef USE_BASIC_ENCRYPTION_MANAGER
#include "encryption/basic-encryption-manager.h"
#endif



#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/bind.hpp>

#include "logging.h"

INIT_LOGGER ("ndn.security.Keychain");

using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  Keychain::Keychain()
    : m_identityManager(Ptr<IdentityManager>::Create())
  {
#ifdef USE_SIMPLE_POLICY_MANAGER
    Ptr<SimplePolicyManager> policyManager = Ptr<SimplePolicyManager>(new SimplePolicyManager());
    Ptr<IdentityPolicyRule> rule1 = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^([^<KEY>]*)<KEY>(<>*)<KSK-.*><ID-CERT>",
                                                                                  "^([^<KEY>]*)<KEY><DSK-.*><ID-CERT>",
                                                                                  ">", "\\1\\2", "\\1", true));
    Ptr<IdentityPolicyRule> rule2 = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^([^<KEY>]*)<KEY><DSK-.*><ID-CERT>",
                                                                                   "^([^<KEY>]*)<KEY>(<>*)<KSK-.*><ID-CERT>",
                                                                                   "==", "\\1", "\\1\\2", true));
    Ptr<IdentityPolicyRule> rule3 = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^(<>*)$", 
                                                                                   "^([^<KEY>]*)<KEY><DSK-.*><ID-CERT>", 
                                                                                   ">", "\\1", "\\1", true));
    policyManager->addVerificationPolicyRule(rule1);
    policyManager->addVerificationPolicyRule(rule2);
    policyManager->addVerificationPolicyRule(rule3);
    
    policyManager->addSigningPolicyRule(rule3);

    m_policyManager = policyManager;
#endif

#ifdef USE_NO_VERIFY_POLICY_MANAGER
    m_policyManager = Ptr<NoVerifyPolicyManager>::Create();
#endif

#ifdef USE_BASIC_ENCRYPTION_MANAGER
    m_encryptionManager = Ptr<EncryptionManager>(new BasicEncryptionManager(m_identityManager->getPrivateStorage(), "/tmp/encryption.db"));
#endif
  }

  Keychain::Keychain(Ptr<IdentityManager> identityManager, 
                     Ptr<PolicyManager> policyManager, 
                     Ptr<EncryptionManager> encryptionManager)
    : m_identityManager(identityManager)
    , m_policyManager(policyManager)
    , m_encryptionManager(encryptionManager)
  {}

  Name
  Keychain::createIdentity(const Name & identity)
  {
    return m_identityManager->createIdentity(identity);
  }

  Name
  Keychain::getDefaultIdentity()
  {
    return m_identityManager->getDefaultIdentity();
  }

  Name
  Keychain::generateRSAKeyPair (const Name & identity, bool ksk, int keySize)
  {
    return m_identityManager->generateRSAKeyPair(identity, ksk, keySize);
  }

  void
  Keychain::setDefaultKeyForIdentity (const Name & keyName, const Name & identity)
  {
    return m_identityManager->setDefaultKeyForIdentity(keyName, identity);
  }

  Name
  Keychain::generateRSAKeyPairAsDefault (const Name & identity, bool ksk, int keySize)
  {
    return m_identityManager->generateRSAKeyPairAsDefault(identity, ksk, keySize);
  }

  Ptr<Blob> 
  Keychain::createSigningRequest(const Name & keyName)
  {
    return Ptr<Blob>(&m_identityManager->getPublickey(keyName)->getKeyBlob());    
  }
  
  void
  Keychain::installIdentityCertificate(Ptr<IdentityCertificate> certificate)
  {
    m_identityManager->addCertificate(certificate);
  }

  void
  Keychain::setDefaultCertificateForKey(const IdentityCertificate & certificate)
  {
    m_identityManager->setDefaultCertificateForKey (certificate);
  }

  Ptr<Certificate> 
  Keychain::getCertificate(const Name & certName)
  {
    return m_identityManager->getCertificate(certName);
  }

  Ptr<Certificate> 
  Keychain::getAnyCertificate(const Name & certName)
  {
    return m_identityManager->getAnyCertificate(certName);
  }

  Ptr<IdentityCertificate> 
  Keychain::getIdentityCertificate(const Name & certificateName)
  {
    return m_identityManager->getCertificate(certificateName);
  }
  
  Ptr<IdentityCertificate> 
  Keychain::getAnyIdentityCertificate(const Name & certificateName)
  {
    return m_identityManager->getAnyCertificate(certificateName);
  }

  void 
  Keychain::revokeKey(const Name & keyName)
  {
    //TODO: Implement
  }

  void
  Keychain::revokeCertificate(const Name & certName)
  {
    //TODO: Implement
  }

  // Ptr<PolicyManager>
  // Keychain::getPolicyManager()
  // { return m_policyManager; }

  // void 
  // Keychain::setSigningPolicyRule(Ptr<PolicyRule> policy)
  // {
  //   m_policyManager->setSigningPolicyRule(policy);
  // }

  // void 
  // Keychain::setVerificationExemption(Ptr<Regex> exempt)
  // {
  //   m_policyManager->setVerificationExemption(exempt);
  // }

  // void 
  // Keychain::setVerificationPolicyRule(Ptr<PolicyRule> policy)
  // {
  //   m_policyManager->setVerificationPolicyRule(policy);
  // }
  
  // void 
  // Keychain::setSigningInference(Ptr<Regex> inference)
  // {
  //   m_policyManager->setSigningInference(inference);
  // }

  // void 
  // Keychain::setTrustAnchor(const Certificate & certificate)
  // {
  //   m_policyManager->setTrustAnchor(certificate);
  // }

  void
  Keychain::sign (Data & data, const Name & certificateName)
  {
    m_identityManager->signByCertificate(data, certificateName);
  }

  Ptr<Signature>
  Keychain::sign (const Blob & blob, const Name & certificateName)
  {
    return m_identityManager->signByCertificate(blob, certificateName);
  }

  void 
  Keychain::signByIdentity(Data & data, const Name & identity)
  {
    Name signingCertificateName;
    if(0 == identity.size())
      {
        Name inferredIdentity = m_policyManager->inferSigningIdentity (data.getName ());
        if(Name() == inferredIdentity)
          signingCertificateName = m_identityManager->getDefaultCertificateName();
        else
          signingCertificateName = m_identityManager->getDefaultCertificateNameByIdentity(inferredIdentity);    
      }
    else
      {
        signingCertificateName = m_identityManager->getDefaultCertificateNameByIdentity(identity);
      }

    if(signingCertificateName.size() == 0)
      throw SecException("No qualified certificate name found!");

    if(!m_policyManager->checkSigningPolicy (data.getName (), signingCertificateName))
      throw SecException("Signing Cert name does not comply with signing policy");

    m_identityManager->signByCertificate(data, signingCertificateName);

  }

  Ptr<Signature> 
  Keychain::signByIdentity (const Blob & blob, const Name & identity)
  {
    Name signingCertificateName = m_identityManager->getDefaultCertificateNameByIdentity(identity);
    
    if(signingCertificateName.size() == 0)
      throw SecException("No qualified certificate name found!");

    return m_identityManager->signByCertificate(blob, signingCertificateName);
  }

  void 
  Keychain::verifyData(Ptr<Data> data, 
                       const DataCallback & verifiedCallback, 
                       const UnverifiedCallback& unverifiedCallback,
                       int stepCount)
  {
    _LOG_TRACE("Enter Verify");

    if(m_policyManager->requireVerify(*data))
      {
        Ptr<ValidationRequest> nextStep = m_policyManager->checkVerificationPolicy(data, 
                                                                                   stepCount,
                                                                                   verifiedCallback,
                                                                                   unverifiedCallback);
        if(NULL != nextStep)
          {
            Ptr<Closure> closure = Ptr<Closure> (new Closure(nextStep->m_verifiedCallback,
                                                             boost::bind(&Keychain::onCertificateInterestTimeout, 
                                                                         this, 
                                                                         _1, 
                                                                         _2, 
                                                                         nextStep->m_retry,
                                                                         unverifiedCallback,
                                                                         data),
                                                             nextStep->m_unverifiedCallback,
                                                             nextStep->m_stepCount)
                                                 );
            
            m_handler->sendInterest(nextStep->m_interest, closure);
          }
      }
    else if(m_policyManager->skipVerifyAndTrust(*data))
      return verifiedCallback(data);
    else
      return unverifiedCallback(data);
  }

  void
  Keychain::onCertificateInterestTimeout(Ptr<Closure> closure, 
                                         Ptr<Interest> interest, 
                                         int retry, 
                                         const UnverifiedCallback& unverifiedCallback,
                                         Ptr<Data> data)
  {
    if(retry > 0)
      {
        Ptr<Closure> newClosure = Ptr<Closure>(new Closure(closure->m_dataCallback,
                                                                  boost::bind(&Keychain::onCertificateInterestTimeout, 
                                                                              this, 
                                                                              _1, 
                                                                              _2, 
                                                                              retry - 1, 
                                                                              unverifiedCallback,
                                                                              data),
                                                                  closure->m_unverifiedCallback,
                                                                  closure->m_stepCount)
                                               );
        m_handler->sendInterest(interest, newClosure);
      }
    else
      unverifiedCallback(data);
  }

  void 
  Keychain::generateSymmetricKey(const Name & keyName, KeyType keyType)
  {
    m_encryptionManager->createSymKey(keyName, keyType);
  }

  Ptr<Blob> 
  Keychain::encrypt(const Name & keyName, const Blob & blob, bool sym, EncryptMode em)
  {
    return m_encryptionManager->encrypt(keyName, blob, sym, em);
  }

  Ptr<Blob> 
  Keychain::decrypt(const Name & keyName, const Blob & blob, bool sym, EncryptMode em)
  {
    return m_encryptionManager->decrypt(keyName, blob, sym, em);
  }
 
}//security

}//ndn
