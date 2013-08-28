/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "keychain.h"

#include "ndn.cxx/wrapper/wrapper.h"
#include "ndn.cxx/wire/ccnb.h"
#include "ndn.cxx/fields/key-locator.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"


#include "identity/basic-identity-storage.h"
#include "policy/policy-rule.h"
#include "policy/basic-policy-manager.h"
#include "encryption/basic-encryption-manager.h"
#include "encoding/der.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/bind.hpp>
#include <cryptopp/rsa.h>

#include "logging.h"

INIT_LOGGER ("ndn.security.Keychain");

using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  Keychain::Keychain(Ptr<PrivatekeyStore> privateStorage, const string & policyPath, const string & encryptionPath)
    :m_maxStep(100)
  {
    m_identityManager = Ptr<IdentityManager>(new IdentityManager(Ptr<BasicIdentityStorage>::Create(), privateStorage));
    m_policyManager = Ptr<PolicyManager>(new BasicPolicyManager(policyPath, privateStorage));
    m_encryptionManager = Ptr<EncryptionManager>(new BasicEncryptionManager(privateStorage, encryptionPath));
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
    return Ptr<Blob>(&m_identityManager->getPublickey(keyName)->getKeyBlob());    
  }
  
  void
  Keychain::installCertificate(Ptr<Certificate> certificatePtr)
  {
    verifyData(certificatePtr, boost::bind(&IdentityManager::addCertificate, &*m_identityManager, certificatePtr), VerifyFailCallback());
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
  Keychain::setSigningPolicyRule(Ptr<PolicyRule> policy)
  {
    m_policyManager->setSigningPolicyRule(policy);
  }

  void 
  Keychain::setVerificationExemption(Ptr<Regex> exempt)
  {
    m_policyManager->setVerificationExemption(exempt);
  }

  void 
  Keychain::setVerificationPolicyRule(Ptr<PolicyRule> policy)
  {
    m_policyManager->setVerificationPolicyRule(policy);
  }
  
  void 
  Keychain::setSigningInference(Ptr<Regex> inference)
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
    Name signingCertName;
    
    if(Name() == signerName)
      signingCertName = m_identityManager->getDefaultCertNameByIdentity(m_policyManager->inferSigningIdentity (data.getName ()));
    else
      {
        if(byID)
          signingCertName = m_identityManager->getDefaultCertNameByIdentity(signerName);
        else
          signingCertName = signerName;
      }

    if(signingCertName.size() == 0)
      throw SecException("No qualified certificate name found!");

    if(!m_policyManager->checkSigningPolicy (data.getName (), signingCertName))
      throw SecException("Signing Cert name does not comply with signing policy");

    m_identityManager->signByCert(data, signingCertName);

  }

  Ptr<Signature> 
  Keychain::sign (const Blob & blob, const Name & signerName, bool byID)
  {
    if(byID)
      return m_identityManager->signByIdentity(blob, signerName);
    else
      return m_identityManager->signByCert(blob, signerName);
  }

  void 
  Keychain::verifyData(Ptr<Data> dataPtr, const VerifiedCallback & verifiedCallback, const VerifyFailCallback & failureCallback)
  {
    _LOG_TRACE("Enter Verify");

    if(m_policyManager->requireVerify(*dataPtr))
      stepVerify(dataPtr, 
                 m_maxStep, 
                 verifiedCallback,
                 failureCallback);  
    else if(m_policyManager->skipVerify(*dataPtr))
      return verifiedCallback(dataPtr);
    else
      return failureCallback();
  }

  static bool 
  verifySignature(const Data & data, const Publickey & publickey)
  {
    using namespace CryptoPP;

    Blob unsignedData(data.getSignedBlob()->signed_buf(), data.getSignedBlob()->signed_size());
    bool result = false;
    
    DigestAlgorithm digestAlg = DIGEST_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType)
      {
        RSA::PublicKey pubKey;
        ByteQueue queue;

        queue.Put((const byte*)publickey.getKeyBlob ().buf (), publickey.getKeyBlob ().size ());
        pubKey.Load(queue);

        if(DIGEST_SHA256 == digestAlg)
          {
            Ptr<const signature::Sha256WithRsa> sigPtr = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data.getSignature());
            const Blob & sigBits = sigPtr->getSignatureBits();

            RSASS<PKCS1v15, SHA256>::Verifier verifier (pubKey);
            result = verifier.VerifyMessage((const byte*) unsignedData.buf(), unsignedData.size(), (const byte*)sigBits.buf(), sigBits.size());            
            _LOG_DEBUG("Signature verified? " << data.getName() << " " << boolalpha << result);
            
          }
      }
   
    return result;
  }

  void
  Keychain::onCertInterestTimeout(Ptr<Closure> closurePtr, Ptr<Interest> interestPtr, int retry, const VerifyFailCallback & failureCallback)
  {
    if(retry > 0)
      {
        Ptr<Closure> newClosurePtr = Ptr<Closure>(new Closure(closurePtr->m_dataCallback,
                                                              boost::bind(&Keychain::onCertInterestTimeout, this, _1, _2, retry - 1, failureCallback),
                                                              closurePtr->m_verifyFailCallback,
                                                              closurePtr->m_unverifiedDataCallback
                                                              ));
        m_handler->sendInterest(interestPtr, newClosurePtr);
      }
    else
      failureCallback();
  }

  void 
  Keychain::onCertVerified(Ptr<Data>signCert, 
                           Ptr<Data>dataPtr, 
                           const RecursiveVerifiedCallback &preRecurVerifyCallback, 
                           const VerifyFailCallback &failureCallback)
  {
    Ptr<Certificate> cert = Ptr<Certificate>(new Certificate(*signCert));
    m_certCache.insert(pair<const Name, const Certificate>(cert->getName(), *cert));

    if(verifySignature(*dataPtr, cert->getPublicKeyInfo()))
      preRecurVerifyCallback(dataPtr);
    else
      failureCallback();
  }

  // void
  // Keychain::onOriginalCertVerified(Ptr<Data>data, 
  //                                  const VerifiedCallback &verifiedCallback, 
  //                                  const VerifyFailCallback &failureCallback)
  // {
  //   m_certCache.insert(pair<const Name, const Certificate>(cert->getName(), *cert));
  //   if(verifySignature(*data, cert->getPublicKeyInfo()))
  //     verifiedCallback();
  //   else
  //     failureCallback();
  // }

  void 
  Keychain::stepVerify(Ptr<Data> dataPtr, const int stepCount, const RecursiveVerifiedCallback & preRecurVerifyCallback, const VerifyFailCallback & failureCallback)
  {
    _LOG_TRACE("Enter StepVerify");

    if(0 == stepCount){
      _LOG_DEBUG("reach the maximum steps of verification");
      return failureCallback();
    }

    _LOG_DEBUG("Check if data comply with policies");
    if(!m_policyManager->checkVerificationPolicy(*dataPtr)){
      _LOG_DEBUG("data does not comply with the policy");
      return failureCallback();
    }
    

    _LOG_DEBUG("Check if keyLocator is trust anchor");
    Ptr<const signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (dataPtr->getSignature());
    
    Ptr<const Certificate> trustedCert = m_policyManager->getTrustAnchor(sha256sig->getKeyLocator().getKeyName());

    if(NULL != trustedCert){
      CertificateData certData(trustedCert->getContent().getContent());
      if(verifySignature(*dataPtr, certData.getKey()))
        {
          return preRecurVerifyCallback(dataPtr);
        }
      else
        return failureCallback();
    }
    else{
      _LOG_DEBUG("KeyLocator is not trust anchor");

      RecursiveVerifiedCallback recursiveVerifiedCallback = boost::bind(&Keychain::onCertVerified, this, _1, dataPtr, preRecurVerifyCallback, failureCallback);

      Ptr<Interest> interestPtr = Ptr<Interest>(new Interest(sha256sig->getKeyLocator().getKeyName()));

      Ptr<Closure> closurePtr = Ptr<Closure> (new Closure(Closure::DataCallback(),
                                                          boost::bind(&Keychain::onCertInterestTimeout, this, _1, _2, 3, failureCallback),
                                                          Closure::VerifyFailCallback(), 
                                                          boost::bind(&Keychain::stepVerify, this, _1, stepCount-1,  recursiveVerifiedCallback, failureCallback)
                                                          )
                                              );

      m_handler->sendInterest(interestPtr, closurePtr);
    }
  }


  Ptr<Data> 
  Keychain::fetchData(const Name & name)
  {
    return fakeFecthData(name);
  }

  Ptr<Data>
  Keychain::fakeFecthData(const Name & name)
  {
    sqlite3 * fakeDB;
    int res = sqlite3_open("/Users/yuyingdi/Test/fake-data.db", &fakeDB);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (fakeDB, "SELECT data_blob FROM data WHERE data_name=?", -1, &stmt, 0);
    
    sqlite3_bind_text(stmt, 1, name.toUri().c_str(), name.toUri().size(), SQLITE_TRANSIENT);

    res = sqlite3_step(stmt);

    if(res == SQLITE_ROW)
      return Data::decodeFromWire(Ptr<Blob>(new Blob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0))));    


    return NULL;
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
