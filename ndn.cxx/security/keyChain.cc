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
#include "ndn.cxx/security/keyChain.h"

#include <boost/date_time/posix_time/posix_time.hpp>

#include "logging.h"

INIT_LOGGER ("KeyChain");

using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  KeyChain::KeyChain()
  {
    //TODO:
  }

  bool KeyChain::CreateIdentity(const string & identity)
  {
    _LOG_TRACE("Enter KeyChain::CreateIdentity");

    if(m_identityDB->IdentityExist(identity)){
      _LOG_DEBUG("Identity has already Exist!");
      return false;
    }

    string keyID;
    if(!GenerateKeyPair(identity, keyID)){
      _LOG_DEBUG("Fail to create a pair of keys!");
      return false;
    }

    _LOG_DEBUG("Successfully create identity!");
    _LOG_TRACE("Exit KeyChain::CreateIdentity");
    return true;
  }

  bool KeyChain::GenerateKeyPair(const string & identity, string & keyID, KeyType keyType, int keySize)
  {
    _LOG_TRACE("Enter KeyChain::GenerateKeyPair");
    

    keyID = m_identityDB->GetNewKeyID(identity);

    string keyName = identity + keyID;

    _LOG_DEBUG("Create a key in private key store")

    if(!m_privateKeyStore->GenerateKeyPair(keyName, keyType, keySize)){
      _LOG_DEBUG("Fail to create a pair of keys!");
      return false;
    }

    _LOG_DEBUG("Create a key record in identity storage");

    Ptr<Blob> keyDigest = Digest(m_privateKeyStore->GetPublicKey(keyName, keyType));
    ptime ts = second_clock::local_time();

    m_identityDB->AddKey(identity, keyID, keyName, keyDigest, ts);
    
    _LOG_DEBUG("Successfully create key pair!");
    _LOG_TRACE("Exit KeyChain::GenerateKeyPair");
    return true;
  }

  Ptr<Blob> KeyChain::CreateSigningRequest(const string & identity, const string & keyID, KeyFormat keyFormat, bool pem)
  {
    _LOG_TRACE("Enter KeyChain::CreateSigningRequest");

    Ptr<Blob> req;

    if(KEY_PUBLIC_OPENSSL == keyFormat){
      _LOG_DEBUG("Try to create a public key in OPENSSL format");
      string keyName = identity + keyID;
      KeyType keyType = KEY_TYPE_RSA; //SHOULD BE REMOVED!!!
      req = m_privateKeyStore->GetPublicKey(keyName, keyType, keyFormat, pem);
    }

    _LOG_TRACE("Exit KeyChain::CreateSigningRequest");
    return req;
  }
  
  bool KeyChain::InstallCertificate(const string & identity, const string & keyID, const Data & certificate)
  {
    _LOG_TRACE("Enter KeyChain::InstallCertificate");

    _LOG_DEBUG("Verify Certificate First");
    if(!Verify(certificate)){
      _LOG_DEBUG("certificate cannot be validated!");
      return false;
    }

    _LOG_DEBUG("Create a certificate record in identity storage")
    
    const Name & certName = certificate.getName();
    int certSeq = 0; //TODO: extract seqNo from name;
    string certType = ""; //TODO: extract cert type from name;

    KeyLocator keyLocator; //TODO::
    if(KeyLocator::KEYNAME != keyLocator.getType()){
      _LOG_DEBUG("Only KEYNAME type keyLocator is supported right now!");
      return false;
    }

    const Name & certSigner = keyLocator.getKeyName();

    const Blob & certData = certificate.getContent().getContent ();
    Certificate cert(certData);

    ptime fresh; //TODO:
    ptime notBefore; //TODO;
    ptime notAfter; //TODO;

    Ptr<Blob> keyDigest = Digest(cert.GetKey());

    Ptr<Blob> certBlob;//TODO;

    m_identityDB->AddCertificate(*keyDigest, certName, certSeq, certType, certSigner, notBefore, notAfter, *certBlob, fresh);

    _LOG_TRACE("Exit KeyChain::InstallCertificate");
    return true;
  }

  Ptr<Blob> KeyChain::GetCertificate(const Name & certName, const Name & certSigner, const string & certType)
  {
    return m_identityDB->GetCertificate(certName, certSigner, certType);
  }

  Ptr<Blob> KeyChain::RevokeKey(const Name & identity, string keyID)
  {
    //TODO: Implement
    return NULL;
  }

  Ptr<Blob> KeyChain::RevokeCertificate(const Name & certName, const int & certSeq)
  {
    //TODO: Implement
    return NULL;
  }

  bool KeyChain::SetSigningPolicy(const string & policy)
  {
    //TODO: Implement
    return false;
  }

  bool KeyChain::SetVerificationPolicy(const string & policy)
  {
    //TODO: Implement
    return false;
  }

  Ptr<Blob> KeyChain::Sign()
  {
    return NULL;
  }

  bool KeyChain::Verify(const Data & data)
  {
    return false;
  }

  Ptr<Blob> KeyChain::GenerateSymmetricKey()
  {
    return NULL;
  }

  Ptr<Blob> KeyChain::Encrypt()
  {
    return NULL;
  }

  Ptr<Blob> KeyChain::Decrypt()
  {
    return NULL;
  }



  Ptr<Blob> KeyChain::Digest(Ptr<Blob> blob)
  {
    //TODO: Implement
    return NULL;
  }
 
}//security

}//ndn
