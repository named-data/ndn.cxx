/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "ndn.cxx/wire/ccnb.h"
#include "ndn.cxx/fields/key-locator.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

#include "keychain.h"
#include "policy/policy.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <cryptopp/rsa.h>

#include "logging.h"

INIT_LOGGER ("Keychain");

using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  Keychain::Keychain()
    :m_maxStep(100)
  {

  }

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
  Keychain::setDefaultKeyForIdentity (const Name & keyName)
  {
    return m_identityManager->setDefaultKeyForIdentity(keyName);
  }

  Name
  Keychain::generateRSAKeyPairAsDefault (const Name & identity, bool ksk, int keySize)
  {
    return m_identityManager->generateRSAKeyPairAsDefault(identity, ksk, keySize);
  }

  Ptr<Blob> 
  Keychain::createSigningRequest(const Name & keyName)
  {
    Ptr<Blob> req;

    return m_identityManager->getPublickey(keyName)->getKeyBlob();    
  }
  
  void
  Keychain::installCertificate(const Certificate & certificate)
  {
    if(!verify(certificate)){
      _LOG_DEBUG("certificate cannot be validated!");
      throw SecException("certificate cannot be validated!");
    }
    
    m_identityManager->addCertificate(certificate);
  }

  Ptr<Certificate> 
  Keychain::getCertificate(const Name & certName)
  {
    return Ptr<Certificate>(new Certificate(*m_identityManager->getCertificate(certName)));
  }

  Ptr<Blob> 
  Keychain::revokeKey(const Name & keyName)
  {
    //TODO: Implement
    return NULL;
  }

  Ptr<Blob> 
  Keychain::revokeCertificate(const Name & certName)
  {
    //TODO: Implement
    return NULL;
  }

  void 
  Keychain::setSigningPolicy(const string & policy)
  {
    m_policyManager->setSigningPolicy(policy);
  }

  void 
  Keychain::setVerificationPolicy(const string & policy)
  {
    m_policyManager->setVerificationPolicy(policy);
  }
  void 
  Keychain::setSigningInference(const string & inference)
  {
    m_policyManager->setSigningInference(inference);
  }

  void 
  Keychain::setTrustAnchor(const Certificate & certificate)
  {
    m_policyManager->setTrustAnchor(certificate);
  }

  void 
  Keychain::sign(Data & data, const Name & signerName, bool byID)
  {
    if(byID)
      {
        Name signingID;

        if(Name() == signerName)
          {
            signingID = m_policyManager->inferSigningCert (data.getName ());
            if(Name () == signingID)
              throw SecException("No qualified identity name found!");
          }
        else
          {
            if(m_policyManager->checkSigningPolicy (data.getName (), signerName))
              signingID = signerName;
            else
              throw SecException("Signing Identity name does not comply with signing policy");
          }

        m_identityManager->signByIdentity(data, signingID);
      }
    else
      {
        Name signingCertName;

        if(Name() == signerName)
          {
            signingCertName = m_policyManager->inferSigningCert (data.getName ());
            if(Name () == signingCertName)
              throw SecException("No qualified cert name found!");
          }
        else
          {
            if(m_policyManager->checkSigningPolicy (data.getName (), signerName))
              signingCertName = signerName;
            else
              throw SecException("Signing cert name does not comply with signing policy");
          }

        m_identityManager->signByCert(data, signingCertName);
      }
  }

  Ptr<Signature> 
  Keychain::sign (const Blob & blob, const Name & signerName, bool byID)
  {
    if(byID)
      return m_identityManager->signByIdentity(blob, signerName);
    else
      return m_identityManager->signByCert(blob, signerName);
  }

  bool 
  Keychain::verify(const Data & data)
  {
    _LOG_TRACE("Enter Verify");

    if(m_policyManager->requireVerify(data))
      return stepVerify(data, m_maxStep);
    else if(m_policyManager->skipVerify(data))
      return true;
    else
      return false;
  }

  bool Keychain::stepVerify(const Data & data, const int & stepCount)
  {
    _LOG_TRACE("Enter StepVerify");

    if(0 == stepCount){
      _LOG_DEBUG("reach the maximum steps of verification");
      return false;
    }

    _LOG_DEBUG("Check if data comply with policies");
    if(!m_policyManager->checkVerificationPolicy(data)){
      _LOG_DEBUG("data does not comply with the policy");
      return false;
    }
    

    _LOG_DEBUG("Check if keyLocator is trust anchor");
    Ptr<const signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data.getSignature());
    
    Ptr<const Certificate> trustedCert = m_policyManager->getTrustAnchor(sha256sig->getKeyLocator().getKeyName());

    if(NULL != trustedCert){
      CertificateData certData(trustedCert->getContent().getContent());
      return verifySignature(data, certData.getKey());
    }
    else{
      _LOG_DEBUG("KeyLocator is not trust anchor");
      Ptr<Data> signCert = fetchData (sha256sig->getKeyLocator().getKeyName());
      if(stepVerify(*signCert, stepCount -1))
        {
          m_certCache.insert(pair<const Name, const Certificate>(signCert->getName(), Certificate(*signCert)));
          return true;
        }
      else
        return false;
    }
  }

  Ptr<Data> Keychain::fetchData(const Name & name)
  {
    return NULL;
  }

  bool 
  Keychain::verifySignature(const Data & data, const Publickey & publickey)
  {
    using namespace CryptoPP;

    Ptr<Blob> unsignedData = data.encodeToUnsignedWire();
    bool result = false;
    
    DigestAlgorithm digestAlg = DIGEST_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType)
      {
        RSA::PublicKey pubKey;
        ByteQueue queue;
        queue.Put((const byte*)publickey.getKeyBlob ()->buf (), publickey.getKeyBlob ()->size ());
        pubKey.Load(queue);

        if(DIGEST_SHA256 == digestAlg)
          {
            Ptr<const signature::Sha256WithRsa> sigPtr = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data.getSignature());
            const Blob & sigBits = sigPtr->getSignatureBits();

            RSASS<PKCS1v15, SHA256>::Verifier verifier (pubKey);
            result = verifier.VerifyMessage((const byte*) unsignedData->buf(), unsignedData->size(), (const byte*)sigBits.buf(), sigBits.size());
          }
      }
   
    return result;
  }

  

  Ptr<Blob> 
  Keychain::generateSymmetricKey()
  {
    return NULL;
  }

  Ptr<Blob> 
  Keychain::encrypt()
  {
    return NULL;
  }

  Ptr<Blob> 
  Keychain::decrypt()
  {
    return NULL;
  }
 
}//security

}//ndn
