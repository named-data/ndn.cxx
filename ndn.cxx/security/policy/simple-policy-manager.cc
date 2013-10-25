/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "simple-policy-manager.h"

#include "identity-policy-rule.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/security/cache/ttl-certificate-cache.h"

#include <boost/bind.hpp>
#include <cryptopp/rsa.h>

#include "logging.h"

INIT_LOGGER("ndn.security.SimplePolicyManager");

using namespace std;

namespace ndn
{

namespace security
{

  SimplePolicyManager::SimplePolicyManager(const int & stepLimit,
					   Ptr<CertificateCache> certificateCache)
    : m_stepLimit(stepLimit)
    , m_certificateCache(certificateCache)
  {
    if(m_certificateCache == NULL)
      m_certificateCache = Ptr<CertificateCache>(new TTLCertificateCache());
  }

  bool
  SimplePolicyManager::requireVerify (const Data & data)
  {
    vector< Ptr<PolicyRule> >::iterator it = m_verifyPolicies.begin();
    for(; it != m_verifyPolicies.end(); it++)
      {
	if((*it)->matchDataName(data))
	  return true;
      }

    it = m_mustFailVerify.begin();
    for(; it != m_mustFailVerify.end(); it++)
      {
	if((*it)->matchDataName(data))
	  return true;
      }

    return false;
  }

  bool 
  SimplePolicyManager::skipVerifyAndTrust (const Data & data)
  {
    vector< Ptr<Regex> >::iterator it = m_verifyExempt.begin();
    for(; it != m_verifyExempt.end(); it++)
      {
	if((*it)->match(data.getName()))
	  return true;
      }

    return false;
  }

  // static bool 
  // verifySignature(const Data & data, const Publickey & publickey)
  // {
  //   using namespace CryptoPP;

  //   Blob unsignedData(data.getSignedBlob()->signed_buf(), data.getSignedBlob()->signed_size());
  //   bool result = false;
    
  //   DigestAlgorithm digestAlg = DIGEST_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
  //   KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
  //   if(KEY_TYPE_RSA == keyType)
  //     {
  //       RSA::PublicKey pubKey;
  //       ByteQueue queue;

  //       queue.Put((const byte*)publickey.getKeyBlob ().buf (), publickey.getKeyBlob ().size ());
  //       pubKey.Load(queue);

  //       if(DIGEST_SHA256 == digestAlg)
  //         {
  //           Ptr<const signature::Sha256WithRsa> sigPtr = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data.getSignature());
  //           const Blob & sigBits = sigPtr->getSignatureBits();

  //           RSASS<PKCS1v15, SHA256>::Verifier verifier (pubKey);
  //           result = verifier.VerifyMessage((const byte*) unsignedData.buf(), unsignedData.size(), (const byte*)sigBits.buf(), sigBits.size());            
  //           _LOG_DEBUG("Signature verified? " << data.getName() << " " << boolalpha << result);
            
  //         }
  //     }
   
  //   return result;
  // }

  void
  SimplePolicyManager::onCertificateVerified(Ptr<Data>signCertificate, 
                                            Ptr<Data>data, 
                                            const DataCallback &verifiedCallback, 
                                            const UnverifiedCallback &unverifiedCallback)
  {
    Ptr<IdentityCertificate> certificate = Ptr<IdentityCertificate>(new IdentityCertificate(*signCertificate));

    if(!certificate->isTooLate() && !certificate->isTooEarly())
      m_certificateCache->insertCertificate(certificate);

    if(verifySignature(*data, certificate->getPublicKeyInfo()))
      verifiedCallback(data);
    else
      unverifiedCallback(data);
  }

  void
  SimplePolicyManager::onCertificateUnverified(Ptr<Data>signCertificate, 
                                              Ptr<Data>data, 
                                              const UnverifiedCallback &unverifiedCallback)
  { unverifiedCallback(data); }

  Ptr<ValidationRequest>
  SimplePolicyManager::checkVerificationPolicy(Ptr<Data> data, 
                                              const int & stepCount, 
                                              const DataCallback& verifiedCallback,
                                              const UnverifiedCallback& unverifiedCallback)
  {
    if(m_stepLimit == stepCount){
      _LOG_DEBUG("reach the maximum steps of verification");
      unverifiedCallback(data);
      return NULL;
    }

    vector< Ptr<PolicyRule> >::iterator it = m_mustFailVerify.begin();
    for(; it != m_mustFailVerify.end(); it++)
      {
	if((*it)->satisfy(*data))
          {
            unverifiedCallback(data);
            return NULL;
          }
      }

    it = m_verifyPolicies.begin();
    for(; it != m_verifyPolicies.end(); it++)
      {
	if((*it)->satisfy(*data))
          {
            Ptr<const signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data->getSignature());    

            if(KeyLocator::KEYNAME != sha256sig->getKeyLocator().getType())
              {
                unverifiedCallback(data);
                return NULL;
              }
	    const Name & keyLocatorName = sha256sig->getKeyLocator().getKeyName();
            Ptr<const IdentityCertificate> trustedCert;
            if(m_trustAnchors.end() == m_trustAnchors.find(keyLocatorName))
              trustedCert = m_certificateCache->getCertificate(keyLocatorName);
	    else
              trustedCert = m_trustAnchors[keyLocatorName];

            if(NULL != trustedCert){
              if(verifySignature(*data, trustedCert->getPublicKeyInfo()))
                {
                  verifiedCallback(data);
                  return NULL;
                }
              else
                unverifiedCallback(data);
                return NULL;
            }
            else{
              _LOG_DEBUG("KeyLocator is not trust anchor");

              DataCallback recursiveVerifiedCallback = boost::bind(&SimplePolicyManager::onCertificateVerified, 
                                                                   this, 
                                                                   _1, 
                                                                   data, 
                                                                   verifiedCallback, 
                                                                   unverifiedCallback);

              UnverifiedCallback recursiveUnverifiedCallback = boost::bind(&SimplePolicyManager::onCertificateUnverified, 
                                                                           this, 
                                                                           _1, 
                                                                           data, 
                                                                           unverifiedCallback);


              Ptr<Interest> interest = Ptr<Interest>(new Interest(sha256sig->getKeyLocator().getKeyName()));

              Ptr<ValidationRequest> nextStep = Ptr<ValidationRequest>(new ValidationRequest(interest, 
                                                                                             recursiveVerifiedCallback,
                                                                                             recursiveUnverifiedCallback,
                                                                                             3,
                                                                                             stepCount + 1)
                                                                       );
              return nextStep;
            }
          }
      }
    
    unverifiedCallback(data);
    return NULL;
  }

  bool 
  SimplePolicyManager::checkSigningPolicy(const Name & dataName, const Name & certName)
  {
    vector< Ptr<PolicyRule> >::iterator it = m_mustFailSign.begin();
    for(; it != m_mustFailSign.end(); it++)
      {
	if((*it)->satisfy(dataName, certName))
	  return false;
      }

    it = m_signPolicies.begin();
    for(; it != m_signPolicies.end(); it++)
      {
	if((*it)->satisfy(dataName, certName))
	  return true;
      }

    return false;
  }
  
  Name
  SimplePolicyManager::inferSigningIdentity(const Name & dataName)
  {
    vector< Ptr<Regex> >::iterator it = m_signInference.begin();
    for(; it != m_signInference.end(); it++)
      {
	if((*it)->match(dataName))
	  return (*it)->expand();
      }

    return Name();
  }

}//security

}//ndn
