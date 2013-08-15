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

#include <ctime>
#include <boost/filesystem.hpp>
#include <fstream>



#include "logging.h"

namespace fs = boost::filesystem;

INIT_LOGGER("ndn.security.IdentityManager")


namespace ndn
{

namespace security
{
  IdentityManager::IdentityManager (Ptr<IdentityStorage> publicStorage, Ptr<PrivatekeyStore> privateStorage)
    :m_publicStorage(publicStorage),
     m_privateStorage(privateStorage)
  {}

  Name
  IdentityManager::createIdentity (const Name & identity)
  {
    if(!m_publicStorage->doesIdentityExist(identity))
      {
	_LOG_DEBUG("Create Identity");
	m_publicStorage->addIdentity(identity);
	
	_LOG_DEBUG("Create Default RSA key pair");
	Name keyName = generateRSAKeyPairAsDefault(identity, true);

	_LOG_DEBUG("Create self-signed certificate");
	Certificate selfCert(*selfSign(keyName)); 
	
	_LOG_DEBUG("Add self-signed certificate as default");

	addCertificateAsDefault(selfCert);

        return keyName;
      }
    else
      throw SecException("Identity has already been created!");
  }

  void
  IdentityManager::loadDefaultIdentity()
  {
    fs::path identityDir = fs::path(getenv("HOME")) / ".ndn-identity";
    ifstream ifs( (identityDir / "default-identity").c_str());
    
    ifs.seekg (0, ios::end);
    ifstream::pos_type size = ifs.tellg();
    // _LOG_DEBUG("Size: " << size);
    char * memblock = new char [size];

    ifs.seekg (0, ios::beg);
    ifs.getline(memblock, size);
    
    Name defaultIdName(memblock);

    if(!m_publicStorage->doesIdentityExist(defaultIdName))
      throw SecException("Identity does not exist!");
    setDefaultIdentity(defaultIdName);

    // _LOG_DEBUG("Default ID: " << default_identity);
  }

  void
  IdentityManager::setDefaultIdentity (const Name & identity)
  {
    m_publicStorage->setDefaultIdentity (identity); 
  }
  
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

  Ptr<Publickey>
  IdentityManager::getPublickey(const Name & keyName)
  {
    return Ptr<Publickey>(new Publickey(*m_publicStorage->getKey(keyName)));
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

  void
  IdentityManager::addCertificateAsIdentityDefault (const Certificate & certificate)
  {
    m_publicStorage->addCertificate(certificate);

    Name keyName = m_publicStorage->getKeyNameForCert(certificate.getName());
    
    setDefaultKeyForIdentity(keyName);

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
    Name keyName = m_publicStorage->getKeyNameForCert(certName);
    
    if(!m_publicStorage->doesKeyExist(keyName))
      throw SecException("No corresponding Key record for certificaite!");

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

  void
  IdentityManager::signByIdentity (Data & data, const Name & identity)
  {
    signByCert(data, m_publicStorage->getDefaultCertNameForIdentity(identity));
  }

  Ptr<Signature>
  IdentityManager::signByCert (const Blob & blob, const Name & certName)
  {    
    Name keyName = m_publicStorage->getKeyNameForCert(certName);
    
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

  void
  IdentityManager::signByCert (Data & data, const Name & certName)
  { 
    Name keyName = m_publicStorage->getKeyNameForCert(certName);
    
    Ptr<Publickey> publickey = m_privateStorage->getPublickey (keyName.toUri());

    //For temporary usage, we support RSA + SHA256 only, but will support more.
    Ptr<signature::Sha256WithRsa> sha256Sig = Ptr<signature::Sha256WithRsa>::Create();
    
    KeyLocator keyLocator;    
    keyLocator.setType (KeyLocator::KEYNAME);
    keyLocator.setKeyName (certName);
    
    sha256Sig->setKeyLocator (keyLocator);
    sha256Sig->setPublisherKeyDigest (*publickey->getDigest ());
    
    data.setSignature(sha256Sig);

    Ptr<Blob> unsignedData = data.encodeToUnsignedWire();

    Ptr<Blob> sigBits = m_privateStorage->sign (*unsignedData, keyName.toUri());

    sha256Sig->setSignatureBits(*sigBits);
  }

  Ptr<Data>
  IdentityManager::selfSign (const Name & keyName)
  {
    Ptr<Data> data = Create<Data>();
    
    // _LOG_DEBUG("Create self-signed cert name");
    Name certName;
    certName.append(keyName).append("ID-CERT").append("0");
    data->setName(certName);

    // _LOG_DEBUG("Get key blob");
    Ptr<Blob> keyBlob = m_publicStorage->getKey(keyName);
    // _LOG_DEBUG("Extract key blob");
    Ptr<Publickey> publickey = Ptr<Publickey>(new Publickey(*keyBlob));

    // _LOG_DEBUG("Generate CertificateData");
    vector< Ptr<CertificateSubDescrypt> > subject;
    subject.push_back(Ptr<CertificateSubDescrypt>(new CertificateSubDescrypt("2.5.4.41", keyName.toUri())));
    tm current = boost::posix_time::to_tm(time::Now());
    current.tm_hour = 0;
    current.tm_min  = 0;
    current.tm_sec  = 0;
    Time notBefore = boost::posix_time::ptime_from_tm(current);
    current.tm_year = current.tm_year + 20;
    Time notAfter = boost::posix_time::ptime_from_tm(current);

    // _LOG_DEBUG("notBefore: " << boost::posix_time::to_iso_string(notBefore) << " notAfter: " << boost::posix_time::to_iso_string(notAfter)); 

    CertificateData certData(notBefore, notAfter, subject, publickey);
    Ptr<Blob> certBlob = certData.toDER();

    // _LOG_DEBUG("certBlob.size: " << certBlob->size());

    Content content(certBlob->buf(), certBlob->size());
    data->setContent(content);

    //For temporary usage, we support RSA + SHA256 only, but will support more.
    Ptr<signature::Sha256WithRsa> sha256Sig = Ptr<signature::Sha256WithRsa>::Create();

    KeyLocator keyLocator;    
    keyLocator.setType (KeyLocator::KEYNAME);
    keyLocator.setKeyName (certName);
    
    sha256Sig->setKeyLocator (keyLocator);
    sha256Sig->setPublisherKeyDigest (*publickey->getDigest ());

    data->setSignature(sha256Sig);

    // _LOG_DEBUG("Prepare for signing");
    Ptr<Blob> unsignedData = data->encodeToUnsignedWire();

    Ptr<Blob> sigBits = m_privateStorage->sign (*unsignedData, keyName.toUri());
    
    // _LOG_DEBUG("Set signature: " << sigBits);
    sha256Sig->setSignatureBits(*sigBits);

    // _LOG_DEBUG("Finish selfSign");

    return data;
  }
  
}//security

}//ndn
