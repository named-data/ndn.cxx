/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */



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
  Keychain::Keychain(int maxStep)
    : m_maxStep(maxStep)
  {
    //TODO:
  }

  bool Keychain::createIdentity(const Name & identity)
  {
    _LOG_TRACE("Enter Keychain::CreateIdentity");

    if(m_identityStorage->doesIdentityExist(identity))
      {
        _LOG_DEBUG("Identity has already Exist!");
        return false;
      }

    generateKeyPair(identity, identity);

    _LOG_DEBUG("Successfully create identity!");
    _LOG_TRACE("Exit Keychain::CreateIdentity");
    return true;
  }

  Name Keychain::generateKeyPair(const Name & identity, const Name & keyName, KeyType keyType, int keySize)
  {
    _LOG_TRACE("Enter Keychain::GenerateKeyPair");
    
    _LOG_DEBUG("Determine keyName")
    Name resultKeyName;
    if(identity == keyName)
      resultKeyName = m_identityStorage->getNewKeyName(identity);
    else
      {
        if(m_identityStorage->doesKeyExist(keyName))
          {
            _LOG_DEBUG("Key name has already existed!");
            throw SecException("Key name has already existed");
          }
        resultKeyName = keyName;
      }

    _LOG_DEBUG("Create a key in private key store");
    if(!m_privatekeyStore->generateKeyPair(resultKeyName.toUri(), keyType, keySize))
      {
        _LOG_DEBUG("Fail to create a pair of keys!");
        throw SecException("Fail to create a pair of keys!");
      }

    _LOG_DEBUG("Create a key record in identity storage");
    Ptr<Blob> keyDigest = m_privatekeyStore->getPublickey(resultKeyName.toUri())->getDigest();
    Time ts = second_clock::universal_time();
    m_identityStorage->addKey(identity, resultKeyName, keyDigest, ts);
    
    _LOG_DEBUG("Successfully create key pair!");
    _LOG_TRACE("Exit Keychain::GenerateKeyPair");
    return resultKeyName;
  }

  Ptr<Blob> Keychain::createSigningRequest(const Name & keyName)
  {
    _LOG_TRACE("Enter Keychain::CreateSigningRequest");

    Ptr<Blob> req;

    _LOG_DEBUG("Try to create a public key in OPENSSL format");

    return m_privatekeyStore->getPublickey(keyName.toUri())->getKeyBlob();    
  }
  
  bool Keychain::installCertificate(const Certificate & certificate)
  {
    _LOG_TRACE("Enter Keychain::InstallCertificate");

    _LOG_DEBUG("Verify Certificate First");
    if(!verify(certificate)){
      _LOG_DEBUG("certificate cannot be validated!");
      return false;
    }

    _LOG_DEBUG("Create a certificate record in identity storage")
    
    m_identityStorage->addCertificate(certificate);

    _LOG_TRACE("Exit Keychain::InstallCertificate");
    return true;
  }

  Ptr<Certificate> Keychain::getCertificate(const Name & certName, const Name & certSigner, const string & certType)
  {
    return m_identityStorage->getCertificate(certName, certSigner, certType);
  }

  Ptr<Blob> Keychain::revokeKey(const Name & keyName)
  {
    //TODO: Implement
    return NULL;
  }

  Ptr<Blob> Keychain::revokeCertificate(const Name & certName)
  {
    //TODO: Implement
    return NULL;
  }

  bool Keychain::setSigningPolicy(const Policy & policy)
  {
    //TODO: Implement
    return m_policyManager->setSigningPolicy(policy);
  }

  bool Keychain::setVerificationPolicy(const Policy & policy)
  {
    //TODO: Implement
    return m_policyManager->setVerificationPolicy(policy);
  }

  void 
  Keychain::sign(Data & data, const Name & certName)
  {
    _LOG_TRACE("Enter Sign");
    
    _LOG_DEBUG("Check Signing certificate comply with policy");    
    Name signingCertName;

    if(Name() == certName)
      {
        Name signingCertName = m_policyManager->getSigningCertName (data.getName ());
        if(Name () == signingCertName)
          throw SecException("No qualified cert name found!");
      }
    else
      {
        if(m_policyManager->checkSigningPolicy (data.getName (), certName))
          signingCertName = certName;
        else
          throw SecException("Signing cert name does not comply with signing policy");
      }

    Ptr<Signature> signature = sign (*data.toUnsignedWire (), signingCertName);
    data.setSignature (signature);

    _LOG_TRACE("Exit Sign");
  }

  Ptr<Signature> 
  Keychain::sign (const Blob & blob, const Name & certName)
  {
    _LOG_TRACE ("Enter Sign");

    string keyName = m_identityStorage->getKeyNameForCert (certName);

    if(keyName == "")
      {
        _LOG_DEBUG ("No qualified key is found!");
        throw SecException ("Corresponding key does not exist in identity storage");
      }

    Ptr<Publickey> publickey = m_privatekeyStore->getPublickey (keyName);

    Ptr<Blob> sigBits = m_privatekeyStore->sign (blob, keyName);

    //For temporary usage, we support RSA + SHA256 only, but will support more.
    Ptr<signature::Sha256WithRsa> sha256Sig = Ptr<signature::Sha256WithRsa>::Create();
    
    KeyLocator keyLocator;    
    keyLocator.setType (KeyLocator::KEYNAME);
    keyLocator.setKeyName (certName);
    
    sha256Sig->setKeyLocator (keyLocator);
    sha256Sig->setPublisherKeyDigest (*publickey->getDigest ());
    sha256Sig->setSignatureBits(*sigBits);

    return boost::dynamic_pointer_cast<Signature>(sha256Sig);
  }

  bool 
  Keychain::verify(const Data & data)
  {
    _LOG_TRACE("Enter Verify");
    
    return stepVerify(data, m_maxStep);
  }

  bool Keychain::stepVerify(const Data & data, const int & stepCount)
  {
    _LOG_TRACE("Enter StepVerify");

    if(0 == stepCount){
      _LOG_DEBUG("reach the maximum steps of verification");
      return false;
    }

    _LOG_DEBUG("Check if there is a policy for the data");
    Ptr<Policy> policy = m_policyManager->getVerificationPolicy(data);
    if(NULL != policy){
      _LOG_DEBUG("No policy is found!");
      return false;
    }

    _LOG_DEBUG("Check if data comply with the policy");
    if(!policy->match(data)){
      _LOG_DEBUG("data does not comply with the policy");
      return false;
    }
    

    _LOG_DEBUG("Check if keyLocator is trust anchor");
    Ptr<Data> trustedCert = m_policyManager->getAnchor(data);

    if(NULL != trustedCert){
      CertificateData certData(trustedCert->getContent().getContent());
      return verifySignature(data, certData.getKey());
    }
    else{
      _LOG_DEBUG("KeyLocator is not trust anchor");
      Ptr<const signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data.getSignature());
      Ptr<Data> signCert = fetchData (sha256sig->getKeyLocator().getKeyName());
      return stepVerify(*signCert, stepCount -1);
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

    Ptr<Blob> unsignedData = data.toUnsignedWire ();
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
