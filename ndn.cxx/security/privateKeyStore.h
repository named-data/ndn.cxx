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
#include "ndn.cxx/security/pubkey.h"
#include "ndn.cxx/security/security-common.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/data.h"


using namespace std;
using namespace ndn;

namespace ndn
{

namespace security
{
  
  class PrivateKeyStore{

  public:
    /**
     * @brief constructor of PrivateKeyStore
     */
    PrivateKeyStore() {};

    /**
     * @brief destructor of PrivateKeyStore
     */    
    virtual ~PrivateKeyStore() {};

    /**
     * @brief generate a pair of asymmetric keys
     * @param keyName the name of the key pair
     * @param keyType the type of the key pair, e.g. RSA
     * @param keySize the size of the key pair
     * @returns true if keys have been successfully generated
     */
    virtual bool GenerateKeyPair(string keyName, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048) = 0;

    /**
     * @brief export public key
     * @param keyName the name of the public key to be exported
     * @param outputFormat the output format of key, e.g. PEM
     * @param outputDir the output directory
     * @returns true if export succeeds
     */
    virtual bool ExportPublicKey(string keyName, KeyType keyType, KeyFormat keyFormat, string outputDir, bool pem) = 0;

    /**
     *
     */
    virtual Ptr<Blob> GetPublicKey(string keyName, KeyType keyType, KeyFormat keyFormat = KEY_PUBLIC_OPENSSL, bool pem = false) = 0;

    /**
     * @brief sign data
     * @param keyName the name of the signing key
     * @param pData the pointer to data
     * @returns signature, NULL if signing fails
     */
    virtual Ptr<Blob> Sign(string keyName, KeyType keyType, DigestAlgorithm digestAlgo, Ptr<Blob> pData) = 0;
    
    /**
     * @brief decrypt data
     * @param keyName the name of the decrypting key
     * @param pData the pointer to encrypted data
     * @returns decrypted data
     */
    virtual Ptr<Blob> Decrypt(string keyName, Ptr<Blob> pData) = 0;


    virtual Ptr<Blob> SignData(const Data & data, string keyName, KeyType, DigestAlgorithm digestAlgo) = 0;

    virtual Ptr<Blob> PublicKeyDigest(string keyName, KeyType keyType, KeyFormat keyFormat, DigestAlgorithm digestAlgo) = 0;

    //TODO Symmetrical key stuff.
    /**
     * @brief generate a symmetric keys
     * @param keyName the name of the key 
     * @param keyType the type of the key, e.g. AES
     * @param keySize the size of the key
     * @returns true if key have been successfully generated
     */
    virtual bool GenerateKey(string keyName, KeyType keyType, int keySize) = 0;



  private:

  };

} //keychain

} //ndn


#endif
