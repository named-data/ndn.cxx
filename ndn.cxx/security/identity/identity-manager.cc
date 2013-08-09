/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "identity-manager.h"

#include "ndn.cxx/fields/key-locator.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

#include "logging.h"

INIT_LOGGER("ndn.security.IdentityManager")

namespace ndn
{

namespace security
{
  IdentityManager::IdentityManager (Ptr<IdentityStorage> publicStorage, Ptr<PrivatekeyStore> privateStorage)
    :m_publicStorage(publicStorage),
     m_privateStorage(privateStorage)
  {}

  void
  IdentityManager::createIdentity (const Name & identity)
  {
    if(!m_publicStorage->doesIdentityExist(identity))
      {
	m_publicStorage->addIdentity(identity);
	
	Name keyName = generateRSAKeyPairAsDefault(identity, true);

	Certificate selfCert(*selfSign(keyName)); 

	addCertificateAsDefault(selfCert);
      }
    else
      throw SecException("Identity has already been created!");
  }

  // void
  // IdentityManager::setDefaultIdentity (const Name & identity)
  // {
  //   m_publicStorage->setDefaultIdentity (identity); 
  // }
  
  Name
  IdentityManager::generateKeyPair (const Name & identity, bool ksk, KeyType keyType, int keySize)
  {
    _LOG_DEBUG("Get new key ID");    
    Name keyName = m_publicStorage->getNewKeyName(identity, ksk);

    _LOG_DEBUG("Generate key pair in private storage");
    if(!m_privateStorage->generateKeyPair(keyName.toUri(), keyType, keySize))
      {
        _LOG_DEBUG("Fail to create a pair of keys!");
        throw SecException("Fail to create a pair of keys!");
      }

    _LOG_DEBUG("Create a key record in public storage");
    Ptr<Publickey> pubKey = m_privateStorage->getPublickey(keyName.toUri());
    m_publicStorage->addKey(keyName, keyType, pubKey->getKeyBlob());
    
    return keyName;
  }

  Name 
  IdentityManager::generateRSAKeyPair (const Name & identity, bool ksk, int keySize)
  {
    return generateKeyPair(identity, ksk, KEY_TYPE_RSA, keySize);
  }

  Name
  IdentityManager::generateRSAKeyPairAsDefault (const Name & identity, bool ksk, int keySize)
  {
    Name keyName = generateKeyPair(identity, ksk, KEY_TYPE_RSA, keySize);

    m_publicStorage->setDefaultKeyName(keyName);
    
    return keyName;
  }

  void
  IdentityManager::setDefaultKeyForIdentity (const Name & keyName)
  {
    m_publicStorage->setDefaultKeyName(keyName);
  }

  Name
  IdentityManager::getDefaultIdentity ()
  {
    return m_publicStorage->getDefaultIdentity();
  }

  void
  IdentityManager::addCertificate (const Certificate & certificate)
  {
    m_publicStorage->addCertificate(certificate);
  }

  void 
  IdentityManager::addCertificateAsDefault (const Certificate & certificate)
  {
    m_publicStorage->addCertificate(certificate);
    
    setDefaultCertForKey(certificate.getName());
  }

  Ptr<Data>
  IdentityManager::getCertificate (const Name & certName)
  {
    return m_publicStorage->getCertificate(certName, false);
  }

  Ptr<Data>
  IdentityManager::getAnyCertificate (const Name & certName)
  {
    return m_publicStorage->getCertificate(certName, true);
  }

  void
  IdentityManager::setDefaultCertForKey (const Name & certName)
  {
    Name keyName = m_publicStorage->getKeyNameForCertExist(certName);

    m_publicStorage->setDefaultCertName (keyName, certName);
  }

  Name
  IdentityManager::getDefaultCertNameByIdentity (const Name & identity)
  {
    return m_publicStorage->getDefaultCertNameForIdentity(identity);
  }
    
  Name
  IdentityManager::getDefaultCertName ()
  {
    return m_publicStorage->getDefaultCertNameForIdentity(getDefaultIdentity());
  }

  Ptr<Signature>
  IdentityManager::signByIdentity (const Blob & blob, const Name & identity)
  {
    return signByCert(blob, m_publicStorage->getDefaultCertNameForIdentity(identity));
  }

  Ptr<Signature>
  IdentityManager::signByCert (const Blob & blob, const Name & certName)
  {    
    Name keyName = m_publicStorage->getKeyNameForCertExist(certName);
    
    Ptr<Publickey> publickey = m_privateStorage->getPublickey (keyName.toUri());

    Ptr<Blob> sigBits = m_privateStorage->sign (blob, keyName.toUri());

    //For temporary usage, we support RSA + SHA256 only, but will support more.
    Ptr<signature::Sha256WithRsa> sha256Sig = Ptr<signature::Sha256WithRsa>::Create();
    
    KeyLocator keyLocator;    
    keyLocator.setType (KeyLocator::KEYNAME);
    keyLocator.setKeyName (certName);
    
    sha256Sig->setKeyLocator (keyLocator);
    sha256Sig->setPublisherKeyDigest (*publickey->getDigest ());
    sha256Sig->setSignatureBits(*sigBits);

    return sha256Sig;
  }

  Ptr<Data>
  IdentityManager::selfSign (const Name & keyName)
  {
    Ptr<Data> data = Create<Data>();
    
    Name certName;
    certName.append(keyName).append("ID-CERT").append("0");
    data->setName(certName);

    Ptr<Blob> keyBlob = m_publicStorage->getKey(keyName);
    Publickey publickey(*keyBlob);

    Content content(keyBlob->buf(), keyBlob->size());
    data->setContent(content);

    Ptr<Blob> unsignedData = data->encodeToWire();
    
    Ptr<Blob> sigBits = m_privateStorage->sign (*unsignedData, keyName.toUri());
    //For temporary usage, we support RSA + SHA256 only, but will support more.
    Ptr<signature::Sha256WithRsa> sha256Sig = Ptr<signature::Sha256WithRsa>::Create();
    
    KeyLocator keyLocator;    
    keyLocator.setType (KeyLocator::KEYNAME);
    keyLocator.setKeyName (certName);
    
    sha256Sig->setKeyLocator (keyLocator);
    sha256Sig->setPublisherKeyDigest (*publickey.getDigest ());
    sha256Sig->setSignatureBits(*sigBits);

    data->setSignature(sha256Sig);

    return data;
  }
  
}//security

}//ndn
