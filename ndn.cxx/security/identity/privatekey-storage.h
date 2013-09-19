/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_PRIVATEKEY_STORAGE_H
#define NDN_PRIVATEKEY_STORAGE_H

#include <string>

#include "ndn.cxx/security/security-common.h"
#include "ndn.cxx/security/certificate/publickey.h"

#include "ndn.cxx/common.h"
#include "ndn.cxx/data.h"
#include "ndn.cxx/fields/blob.h"


namespace ndn
{

namespace security
{
  
  class PrivatekeyStorage{

  public:
    /**
     * @brief constructor of PrivateKeyStore
     */
    PrivatekeyStorage() {};

    /**
     * @brief destructor of PrivateKeyStore
     */    
    virtual 
    ~PrivatekeyStorage() {};

    /**
     * @brief generate a pair of asymmetric keys
     * @param keyName the name of the key pair
     * @param keyType the type of the key pair, e.g. RSA
     * @param keySize the size of the key pair
     */
    virtual void 
    generateKeyPair(const Name & keyName, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048) = 0;

    /**
     * @brief get the public key
     * @param keyName the name of public key
     * @return the public key
     */
    virtual Ptr<Publickey> 
    getPublickey(const Name & keyName) = 0;

    /**
     * @brief sign data blob
     * @param blob the blob to be signed
     * @param keyName the name of the signing key
     * @param digestAlgo the digest algorithm
     * @returns signature, NULL if signing fails
     */
    virtual Ptr<Blob> 
    sign(const Blob & blob, const Name & keyName, DigestAlgorithm digestAlgo = DIGEST_SHA256) = 0;
    
    /**
     * @brief decrypt data
     * @param keyName the name of the decrypting key
     * @param blob the blob to be decrypted
     * @param sym if true symmetric encryption is used, otherwise asymmetric decryption is used.
     * @returns decrypted data
     */
    virtual Ptr<Blob> 
    decrypt(const Name & keyName, const Blob & data, bool sym = false) = 0;

    /**
     * @brief encrypt data
     * @param keyName the name of the encrypting key
     * @param blob the blob to be encrypted
     * @param sym if true symmetric encryption is used, otherwise asymmetric decryption is used.
     * @returns encrypted data
     */
    virtual Ptr<Blob> 
    encrypt(const Name & keyName, const Blob & pData, bool sym = false) = 0;


    /**
     * @brief generate a symmetric key
     * @param keyName the name of the key 
     * @param keyType the type of the key, e.g. AES
     * @param keySize the size of the key
     */
    virtual void 
    generateKey(const Name & keyName, KeyType keyType = KEY_TYPE_AES, int keySize = 256) = 0;

    /**
     * @brief check if a particular key exist
     * @param keyName the name of the key
     * @param keyClass the class of the key, e.g. public, private, or symmetric
     * @return true if the key exists, otherwise false
     */
    virtual bool
    doesKeyExist(const Name & keyName, KeyClass keyClass) = 0;


  private:

  };

} //security

} //ndn


#endif
