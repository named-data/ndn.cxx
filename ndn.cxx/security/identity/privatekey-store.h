/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_PRIVATEKEY_STORE_H
#define NDN_PRIVATEKEY_STORE_H

#include <string>
#include "ndn.cxx/security/security-common.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/data.h"

#include "ndn.cxx/security/certificate/publickey.h"

namespace ndn
{

namespace security
{
  
  class PrivatekeyStore{

  public:
    /**
     * @brief constructor of PrivateKeyStore
     */
    PrivatekeyStore() {};

    /**
     * @brief destructor of PrivateKeyStore
     */    
    virtual 
    ~PrivatekeyStore() {};

    /**
     * @brief generate a pair of asymmetric keys
     * @param keyName the name of the key pair
     * @param keyType the type of the key pair, e.g. RSA
     * @param keySize the size of the key pair
     * @returns true if keys have been successfully generated
     */
    virtual bool 
    generateKeyPair(const string & keyName, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048) = 0;

    /**
     *
     */
    virtual Ptr<Publickey> 
    getPublickey(const string & keyName) = 0;

    /**
     * @brief sign data
     * @param keyName the name of the signing key
     * @param digestAlgo the digest algorithm
     * @param pData the pointer to data
     * @returns signature, NULL if signing fails
     */
    virtual Ptr<Blob> 
    sign(const Blob & pData, const string & keyName, DigestAlgorithm digestAlgo = DIGEST_SHA256) = 0;
    
    /**
     * @brief decrypt data
     * @param keyName the name of the decrypting key
     * @param pData the pointer to encrypted data
     * @returns decrypted data
     */
    virtual Ptr<Blob> 
    decrypt(const string & keyName, const Blob & pData, bool sym = false) = 0;

    virtual Ptr<Blob> 
    encrypt(const string & keyName, const Blob & pData, bool sym = false) = 0;


    //TODO Symmetrical key stuff.
    /**
     * @brief generate a symmetric keys
     * @param keyName the name of the key 
     * @param keyType the type of the key, e.g. AES
     * @param keySize the size of the key
     * @returns true if key have been successfully generated
     */
    virtual bool 
    generateKey(const string & keyName, KeyType keyType = KEY_TYPE_AES, int keySize = 256) = 0;



  private:

  };

} //keychain

} //ndn


#endif
