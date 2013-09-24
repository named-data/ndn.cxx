/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_OSX_PRIVATEKEY_STORAGE_H
#define NDN_OSX_PRIVATEKEY_STORAGE_H

#include "ndn.cxx/common.h"

#include "privatekey-storage.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

namespace ndn
{

namespace security
{
  class OSXPrivatekeyStorage : public PrivatekeyStorage
  {
  public:

    /**
     * @brief constructor of OSXPrivatekeyStorage
     * @param keychainName the name of keychain
     */
    OSXPrivatekeyStorage(const string & keychainName = "");

    /**
     * @brief destructor of OSXPrivateKeyStore
     */    
    virtual 
    ~OSXPrivatekeyStorage();

    /**
     * @brief generate a pair of asymmetric keys
     * @param keyName the name of the key pair
     * @param keyType the type of the key pair, e.g. RSA
     * @param keySize the size of the key pair
     */
    virtual void 
    generateKeyPair(const Name & keyName, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048);

    /**
     * @brief get public key by key name
     * @param keyName the name of the key pair
     * @returns public key
     */
    virtual Ptr<Publickey> 
    getPublickey(const Name & keyName);

    /**
     * @brief sign data
     * @param pData data to be signed
     * @param keyName the name of the signing key
     * @param digestAlgo the digest algorithm
     * @returns signature, NULL if signing fails
     */
    virtual Ptr<Blob> 
    sign(const Blob & pData, const Name & keyName, DigestAlgorithm digestAlgo = DIGEST_SHA256);
    
    /**
     * @brief decrypt data
     * @param keyName the name of the decrypting key
     * @param pData the decrypted data
     * @param sym decrypt mode, symmetric encryption if true, otherwise asymmetric encryption
     * @returns decrypted data
     */
    virtual Ptr<Blob> 
    decrypt (const Name & keyName, const Blob & pData, bool sym = false);

    /**
     * @brief encrypt data
     * @param keyName the name of the encrypting key
     * @param pData the encrypted data
     * @param sym decrypt mode, symmetric encryption if true, otherwise asymmetric encryption
     * @returns encrypted data
     */
    virtual Ptr<Blob> 
    encrypt (const Name & keyName, const Blob & pData, bool sym = false);


    /**
     * @brief generate a symmetric key
     * @param keyName the name of the key 
     * @param keyType the type of the key, e.g. AES
     * @param keySize the size of the key
     */
    virtual void 
    generateKey(const Name & keyName, KeyType keyType = KEY_TYPE_AES, int keySize = 256);

    /**
     * @brief check if a key name has existed
     * @param keyName the name of the key
     * @param keyClass the class of the key, e.g. Private Key
     * @returns true if the keyname exists
     */
    virtual bool 
    doesKeyExist(const Name & keyName, KeyClass keyClass);

    /**
     * @brief configure ACL of a particular key
     * @param keyName the name of key
     * @param keyClass the class of key, e.g. Private Key
     * @param acl the new acl of the key
     * @param appPath the absolute path to the application
     * @returns true if setting succeeds
     */
    bool 
    setACL (const Name & keyName, KeyClass keyClass, int acl, const string & appPath);

    /**
     * @brief verify data (test only)
     * @param keyName the name of key
     * @param pData the data to be verified
     * @param pSig the signature associated with the data
     * @param digestAlgo digest algorithm
     * @return true if signature can be verified, otherwise false
     */
    bool 
    verifyData (const Name & keyName, const Blob & pData, const Blob & pSig, DigestAlgorithm digestAlgo = DIGEST_SHA256);


  private:
    /**
     * @brief convert NDN name of a key to internal name of the key
     * @param keyName the NDN name of the key
     * @param keyClass the class of the key
     * @return the internal key name
     */
    string 
    toInternalKeyName(const Name & keyName, KeyClass keyClass);

    /**
     * @brief Get key
     * @param keyName the name of the key
     * @param keyClass the class of the key
     * @returns pointer to the key
     */
    SecKeychainItemRef 
    getKey (const Name & keyName, KeyClass keyClass);
      
    /**
     * @brief convert keyType to MAC OS symmetric key key type
     * @param keyType
     * @returns MAC OS key type
     */
    const CFTypeRef 
    getSymKeyType(KeyType keyType);

    /**
     * @brief convert keyType to MAC OS asymmetirc key type
     * @param keyType
     * @returns MAC OS key type
     */
    const CFTypeRef 
    getAsymKeyType(KeyType keyType);

    /**
     * @brief convert keyClass to MAC OS key class
     * @param keyClass
     * @returns MAC OS key class
     */
    const CFTypeRef 
    getKeyClass(KeyClass keyClass);

    /**
     * @brief convert digestAlgo to MAC OS algorithm id
     * @param digestAlgo
     * @returns MAC OS algorithm id
     */
    const CFStringRef 
    getDigestAlgorithm(DigestAlgorithm digestAlgo);

    /**
     * @brief convert format to MAC OS key format
     * @param format
     * @returns MAC OS keyformat
     */
    SecExternalFormat 
    getFormat(KeyFormat format);

    // string prependSymKeyName(const string & externalKeyName);

    /**
     * @brief get the digest size of the corresponding algorithm
     * @param digestAlgo the digest algorithm
     * @return digest size
     */
    long 
    getDigestSize(DigestAlgorithm digestAlgo);

  private:
    const string m_keychainName;
    SecKeychainRef m_keychainRef;
    SecKeychainRef m_originalDefaultKeychain;
  };
  
}//security

}//ndn

#endif
