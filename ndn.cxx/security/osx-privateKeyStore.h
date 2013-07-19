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

#include <string>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

#include "ndn.cxx/security/privateKeyStore.h"

using namespace std;
using namespace ndn;

namespace ndn
{

namespace security
{
  class OSXPrivateKeyStore : public PrivateKeyStore
  {
  public:

    /**
     * @brief constructor of OSXPrivateKeyStore
     * @param keychainName the name of keychain
     */
    OSXPrivateKeyStore(string keychainName = "");

    /**
     * @brief destructor of OSXPrivateKeyStore
     */    
    virtual ~OSXPrivateKeyStore();

    /**
     * @brief generate a pair of asymmetric keys
     * @param keyName the name of the key pair
     * @param keyType the type of the key pair, e.g. RSA
     * @param keySize the size of the key pair
     * @returns true if keys have been successfully generated
     */
    virtual bool GenerateKeyPair(string keyName, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048);

    /**
     * @brief export public key
     * @param keyName the name of the public key to be exported
     * @param outputFormat the output format of key, e.g. PEM
     * @param outputDir the output directory
     * @returns true if export succeeds
     */
    virtual bool ExportPublicKey(string keyName, KeyType keyType, KeyFormat keyFormat, string outputDir);

    /**
     * @brief sign data
     * @param keyName the name of the signing key
     * @param pData the pointer to data
     * @returns signature, NULL if signing fails
     */
    virtual Ptr<Blob> Sign(string keyName, KeyType keyType, DigestAlgorithm digestAlgo, Ptr<Blob> pData);
    
    /**
     * @brief decrypt data
     * @param keyName the name of the decrypting key
     * @param pData the pointer to encrypted data
     * @returns decrypted data
     */
    virtual Ptr<Blob> Decrypt(string keyName, Ptr<Blob> pData);

    //TODO Symmetrical key stuff.
    /**
     * @brief generate a symmetric keys
     * @param keyName the name of the key 
     * @param keyType the type of the key, e.g. AES
     * @param keySize the size of the key
     * @returns true if key have been successfully generated
     */
    virtual bool GenerateKey(string keyName, KeyType keyType, int keySize);

    /**
     * @brief configure ACL of a particular key
     * @param keyName the name of key
     * @param keyType the type of key, e.g. RSA
     * @param keyClass the class of key, e.g. Private Key
     * @param acl the new acl of the key
     * @returns true if setting succeeds
     */
    bool SetACL(string keyName, KeyType keyType, KeyClass keyClass, int acl, string appPath);

    //Test
    bool Verify(string keyName, KeyType keyType, DigestAlgorithm digestAlgo, Ptr<Blob> pData, Ptr<Blob>pSig);

    Ptr<Blob> Encrypt(string keyName, Ptr<Blob> pData);

  private:
    /**
     * @brief check if a keyname has existed
     * @param keyName the name of the key
     * @param keyClass the class of the key, e.g. Private Key
     * @returns true if the keyname exists
     */
    bool NameExists(string keyName, KeyClass keyClass);

    /**
     * @brief fetch key
     * @param keyName the name of the key
     * @param keyType the type of the key
     * @param keyClass the class of the key
     * @returns pointer to the key
     */
    SecKeychainItemRef FetchKey(string keyName, KeyType keyType, KeyClass keyClass);
      
    /**
     * @brief convert keyType to MAC OS key type
     * @param keyType
     * @returns MAC OS key type
     */
    const CFTypeRef GetKeyType(KeyType keyType);

    /**
     * @brief convert keyClass to MAC OS key class
     * @param keyClass
     * @returns MAC OS key class
     */
    const CFTypeRef GetKeyClass(KeyClass keyClass);

    /**
     * @brief convert digestAlgo to MAC OS algorithm id
     * @param digestAlgo
     * @returns MAC OS algorithm id
     */
    const CFStringRef GetDigestAlgorithm(DigestAlgorithm digestAlgo);

     /**
     * @brief convert format to MAC OS key format
     * @param format
     * @returns MAC OS keyformat
     */
    SecExternalFormat GetFormat(KeyFormat format);

  private:
    const string m_keychainName;
    SecKeychainRef m_keychainRef;
    SecKeychainRef m_originalDefaultKeychain;
  };
  
}//security

}//ndn

#endif
