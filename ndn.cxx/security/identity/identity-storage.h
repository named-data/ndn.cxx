/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_IDENTITY_STORAGE_H
#define NDN_IDENTITY_STORAGE_H

#include "ndn.cxx/security/security-common.h"
#include "ndn.cxx/security/certificate/identity-certificate.h"

using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  /**
   * @brief IdentityStorage class, the storage for identity, public key, and certificate. Private keys are stored in PrivatekeyStorage.
   */
  class IdentityStorage
  {
  public:
    /**
     * @brief constructor
     */
    IdentityStorage() {}

    /**
     * @brief destructor
     */
    virtual 
    ~IdentityStorage () {}

    /**
     * @brief check if the specified identity has already existed
     * @param identity the name of the identity
     * @return true if the identity exists, otherwise false
     */
    virtual bool 
    doesIdentityExist (const Name & identity) = 0;

    /**
     * @brief add a new identity. Exception will be thrown out, if identity already exists
     * @param the identity to be added
     */
    virtual void
    addIdentity (const Name & identity) = 0;

    /**
     * @brief revoke identity
     */
    virtual bool 
    revokeIdentity () = 0;


    /**
     * @brief generate a name for a new key of the identity
     * @param identity
     * @param ksk generate a KSK name if true, DSK name otherwise
     * @return the generated key name
     */
    virtual Name 
    getNewKeyName (const Name & identity, bool ksk) = 0;

    /**
     * @brief check if the specified key has already existed
     * @param keyName the name of the key
     * @return true if the key exists, otherwise false
     */
    virtual bool 
    doesKeyExist (const Name & keyName) = 0;

    /**
     * @brief extract key name from certificate name
     * @param certificateName the certificate name to be processed
     */
    virtual Name 
    getKeyNameForCertificate (const Name & certificateName) = 0;

    /**
     * @brief add a public key in to identity storage
     * @param keyName name of the public key to be added
     * @param keyType type of the public key to be added
     * @param publicKeyBlob blob of the public key to be added
     */
    virtual void 
    addKey (const Name & keyName, KeyType keyType, Blob & publicKeyBlob) = 0;

    /**
     * @brief get the public key blob from the identity storage
     * @param keyName name of the requested public key
     */
    virtual Ptr<Blob>
    getKey (const Name & keyName) = 0;

    /**
     * @brief activate key, if a key is marked as inactive, its private part will not be used in packet signing
     * @param keyName name of the key
     */
    virtual void 
    activateKey (const Name & keyName) = 0;

    /**
     * @brief deactivate key, if a key is marked as inactive, its private part will not be used in packet signing
     * @param keyName name of the key
     */
    virtual void 
    deactivateKey (const Name & keyName) = 0;

    /**
     * @brief check if the specified certificate has already existed
     * @param certificateName the name of the certificate
     * @return true if the certificate exists, otherwise false
     */
    virtual bool
    doesCertificateExist (const Name & certificateName) = 0;

    /**
     * @brief add a certificate in to identity storage
     * @param certificate the certificate to be added
     */
    virtual void 
    addCertificate (Ptr<IdentityCertificate> certificate) = 0;

    /**
     * @brief get a certificate from identity storage
     * @param certificateName the name of the requested certificate
     * @param any if false, only valid certifcate will be returned, otherwise validity is disregarded
     * @return requested certificate 
     */
    virtual Ptr<Data> 
    getCertificate (const Name & certificateName, bool any = false) = 0;


    /*****************************************
     *           Get/Set Default             *
     *****************************************/

    /**
     * @brief get default identity 
     * @param return the name of default identity
     */
    virtual Name 
    getDefaultIdentity () = 0;

    /**
     * @brief get default key name of specified identity
     * @param identity
     * @return the default key name
     */
    virtual Name 
    getDefaultKeyNameForIdentity (const Name & identity) = 0;

    /**
     * @brief get default certificate name of specified identity
     * @param identity
     * @return the default certificate name
     */
    inline Name 
    getDefaultCertificateNameForIdentity (const Name & identity);

    /**
     * @brief get default certificate name of specified key
     * @param keyName
     * @return the default certificate name
     */
    virtual Name 
    getDefaultCertificateNameForKey (const Name & keyName) = 0;

    /**
     * @brief set the default identity
     * @param identity default identity name
     */
    virtual void 
    setDefaultIdentity (const Name & identity) = 0;

    /**
     * @brief set the default key name of the specified identity
     * @param keyName
     * @param identity
     */
    virtual void 
    setDefaultKeyNameForIdentity (const Name & keyName, const Name & identity = Name()) = 0;

    /**
     * @brief set the default key name of the specified identity
     * @param keyName
     * @param certificateName
     */
    virtual void 
    setDefaultCertificateNameForKey (const Name & keyName, const Name & certificateName) = 0;

  };

  inline Name 
  IdentityStorage::getDefaultCertificateNameForIdentity (const Name & identity)
  {
    Name keyName = getDefaultKeyNameForIdentity(identity);
    
    return getDefaultCertificateNameForKey(keyName);
  }

}//security

}//ndn

#endif
