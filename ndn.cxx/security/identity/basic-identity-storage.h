/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_BASIC_IDENTITY_STORAGE_H
#define NDN_BASIC_IDENTITY_STORAGE_H

#include <sqlite3.h>

#include "ndn.cxx/common.h"

#include "identity-storage.h"

namespace ndn
{

namespace security
{
  /**
   * @brief BasicIdentityStorage class, a basic implementation of IdentityStorage
   */
  class BasicIdentityStorage : public IdentityStorage
  {
  public:
    /**
     * @brief constructor
     */
    BasicIdentityStorage();

    /**
     * @brief destructor
     */
    virtual ~BasicIdentityStorage() {}

    /**
     * @brief check if the specified identity has already existed
     * @param identity the name of the identity
     * @return true if the identity exists, otherwise false
     */
    virtual bool 
    doesIdentityExist (const Name & identity);

    /**
     * @brief add a new identity. Exception will be thrown out, if identity already exists
     * @param the identity to be added
     */
    virtual void
    addIdentity (const Name & identity);

    /**
     * @brief revoke identity
     */
    virtual bool 
    revokeIdentity ();

    /**
     * @brief check if the specified key has already existed
     * @param keyName the name of the key
     * @return true if the key exists, otherwise false
     */
    virtual bool 
    doesKeyExist (const Name & keyName);

    /**
     * @brief add a public key in to identity storage
     * @param keyName name of the public key to be added
     * @param keyType type of the public key to be added
     * @param publicKeyBlob blob of the public key to be added
     */
    virtual void 
    addKey (const Name & keyName, KeyType keyType, Blob & pubKeyBlob);

    /**
     * @brief get the public key blob from the identity storage
     * @param keyName name of the requested public key
     */
    virtual Ptr<Blob>
    getKey (const Name & keyName);

    /**
     * @brief activate key, if a key is marked as inactive, its private part will not be used in packet signing
     * @param keyName name of the key
     */
    virtual void 
    activateKey (const Name & keyName);

    /**
     * @brief deactivate key, if a key is marked as inactive, its private part will not be used in packet signing
     * @param keyName name of the key
     */
    virtual void 
    deactivateKey (const Name & keyName);


    /**
     * @brief check if the specified certificate has already existed
     * @param certificateName the name of the certificate
     * @return true if the certificate exists, otherwise false
     */
    virtual bool 
    doesCertificateExist (const Name & certName);

    /**
     * @brief add a certificate in to identity storage without checking if identity and key exists
     * @param certificate the certificate to be added
     */
    void
    addAnyCertificate (Ptr<IdentityCertificate> certificate);

    /**
     * @brief add a certificate in to identity storage
     * @param certificate the certificate to be added
     */
    virtual void 
    addCertificate (Ptr<IdentityCertificate> certificate);

    /**
     * @brief get a certificate from identity storage
     * @param certificateName the name of the requested certificate
     * @param any if false, only valid certifcate will be returned, otherwise validity is disregarded
     * @return requested certificate 
     */
    virtual Ptr<Data> 
    getCertificate (const Name & certName, bool any = false);

    /**
     * @brief get default identity 
     * @param return the name of default identity
     */
    virtual Name 
    getDefaultIdentity ();

    /**
     * @brief get default key name of specified identity
     * @param identity
     * @return the default key name
     */
    virtual Name 
    getDefaultKeyNameForIdentity (const Name & identity);
    
    /**
     * @brief get default certificate name of specified key
     * @param keyName
     * @return the default certificate name
     */
    virtual Name 
    getDefaultCertificateNameForKey (const Name & keyName);

    /**
     * @brief set the default identity
     * @param identity default identity name
     */
    virtual void 
    setDefaultIdentity (const Name & identity);

    /**
     * @brief set the default key name of the specified identity
     * @param keyName
     * @param identity
     */
    virtual void 
    setDefaultKeyNameForIdentity (const Name & keyName, const Name & identity = Name());

    /**
     * @brief set the default key name of the specified identity
     * @param keyName
     * @param certificateName
     */
    virtual void 
    setDefaultCertificateNameForKey (const Name & keyName, const Name & certificateName);

  private:

    virtual void
    updateKeyStatus(const Name & keyName, bool active);

  private:
    sqlite3 *m_db;
    Time m_lastUpdated;
  };

}//security

}//ndn


#endif
