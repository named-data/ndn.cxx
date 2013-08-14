/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_OSX_PRIVATEKEY_STORE_H
#define NDN_OSX_PRIVATEKEY_STORE_H

#include "ndn.cxx/common.h"

#include "privatekey-store.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

namespace ndn
{

namespace security
{
  class OSXPrivatekeyStore : public PrivatekeyStore
  {
  public:

    /**
     * @brief constructor of OSXPrivatekeyStore
     * @param keychainName the name of keychain
     */
    OSXPrivatekeyStore(const string & keychainName = "");

    /**
     * @brief destructor of OSXPrivateKeyStore
     */    
    virtual ~OSXPrivatekeyStore();

    /**
     * @brief generate a pair of asymmetric keys
     * @param keyName the name of the key pair
     * @param keyType the type of the key pair, e.g. RSA
     * @param keySize the size of the key pair
     * @returns true if keys have been successfully generated
     */
    virtual bool generateKeyPair(const string & keyName, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048);

    /**
     * @brief get public key by key name
     * @param keyName the name of the key pair
     * @returns public key
     */
    virtual Ptr<Publickey> getPublickey(const string & keyName);

    /**
     * @brief sign data
     * @param keyName the name of the signing key
     * @param digestAlgo the digest algorithm
     * @param pData the pointer to data
     * @returns signature, NULL if signing fails
     */
    virtual Ptr<Blob> sign(const Blob & pData, const string & keyName, DigestAlgorithm digestAlgo = DIGEST_SHA256);
    
    /**
     * @brief decrypt data
     * @param keyName the name of the decrypting key
     * @param pData the pointer to encrypted data
     * @returns decrypted data
     */
    virtual Ptr<Blob> decrypt (const string & keyName, const Blob & pData, bool sym = false);

    virtual Ptr<Blob> encrypt (const string & keyName, const Blob & pData, bool sym = false);

    //TODO Symmetrical key stuff.
    /**
     * @brief generate a symmetric keys
     * @param keyName the name of the key 
     * @param keyType the type of the key, e.g. AES
     * @param keySize the size of the key
     * @returns true if key have been successfully generated
     */
    virtual bool generateKey(const string & keyName, KeyType keyType = KEY_TYPE_AES, int keySize = 256);

    /**
     * @brief configure ACL of a particular key
     * @param keyName the name of key
     * @param keyType the type of key, e.g. RSA
     * @param keyClass the class of key, e.g. Private Key
     * @param acl the new acl of the key
     * @returns true if setting succeeds
     */
    bool setACL (const string & keyName, KeyClass keyClass, int acl, const string & appPath);

    bool verifyData (const string & keyName, const Blob & pData, const Blob & pSig, DigestAlgorithm digestAlgo = DIGEST_SHA256);

    

  private:
    /**
     * @brief check if a keyname has existed
     * @param keyName the name of the key
     * @param keyClass the class of the key, e.g. Private Key
     * @returns true if the keyname exists
     */
    bool doesNameExist(string keyName, KeyClass keyClass);

    /**
     * @brief Get key
     * @param keyName the name of the key
     * @param keyClass the class of the key
     * @returns pointer to the key
     */
    SecKeychainItemRef getKey(string keyName, KeyClass keyClass);
      
    /**
     * @brief convert keyType to MAC OS key type
     * @param keyType
     * @returns MAC OS key type
     */
    const CFTypeRef getSymKeyType(KeyType keyType);

    const CFTypeRef getAsymKeyType(KeyType keyType);

    /**
     * @brief convert keyClass to MAC OS key class
     * @param keyClass
     * @returns MAC OS key class
     */
    const CFTypeRef getKeyClass(KeyClass keyClass);

    /**
     * @brief convert digestAlgo to MAC OS algorithm id
     * @param digestAlgo
     * @returns MAC OS algorithm id
     */
    const CFStringRef getDigestAlgorithm(DigestAlgorithm digestAlgo);

     /**
     * @brief convert format to MAC OS key format
     * @param format
     * @returns MAC OS keyformat
     */
    SecExternalFormat getFormat(KeyFormat format);

    string prependSymKeyName(const string & externalKeyName);

    long getDigestSize(DigestAlgorithm digestAlgo);

  private:
    const string m_keychainName;
    SecKeychainRef m_keychainRef;
    SecKeychainRef m_originalDefaultKeychain;
  };
  
}//security

}//ndn

#endif
