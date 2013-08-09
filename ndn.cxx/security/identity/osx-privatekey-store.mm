/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "logging.h"

#include "osx-privatekey-store.h"

#include "ndn.cxx/security/certificate/der.h"
#include "ndn.cxx/wire/ccnb.h"

#include <fstream>
#include <sstream>

#include <CoreFoundation/CoreFoundation.h>

using namespace std;

INIT_LOGGER ("OSXPrivatekeyStore");

namespace ndn
{

namespace security
{

  OSXPrivatekeyStore::OSXPrivatekeyStore (const string & keychainName)
    : m_keychainName("" == keychainName ?  "NDN.keychain" : keychainName)
  {
    _LOG_TRACE ("Enter: OSXPrivatekeyStore Constructor");
   
    OSStatus res = SecKeychainCreate (m_keychainName.c_str (), //Keychain path
                                      0,                       //Keychain password length
                                      NULL,                    //Keychain password
                                      true,                    //User prompt
                                      NULL,                    //Initial access of Keychain
                                      &m_keychainRef);         //Keychain reference

    if (res == errSecDuplicateKeychain)
      res = SecKeychainOpen (m_keychainName.c_str (),
                             &m_keychainRef);

    if (res != errSecSuccess){
      _LOG_DEBUG ("Fail to initialize keychain ref: " << res);
      throw SecException("Fail to initialize keychain ref");
    }

    res = SecKeychainCopyDefault (&m_originalDefaultKeychain);

    res = SecKeychainSetDefault (m_keychainRef);
    if (res != errSecSuccess){
      _LOG_DEBUG ("Fail to set default keychain: " << res);
      throw SecException("Fail to set default keychain");
    }
  }

  OSXPrivatekeyStore::~OSXPrivatekeyStore (){
    //TODO: implement
  }

  bool OSXPrivatekeyStore::generateKeyPair(const string & keyName, KeyType keyType, int keySize)
  {
    _LOG_TRACE("OSXPrivatekeyStore::GenerateKeyPair");
    
    if(doesNameExist(keyName, KEY_CLASS_PUBLIC)){
      _LOG_DEBUG("keyName has exists!")
      return false;
    }

    SecKeyRef publicKey, privateKey;

    CFStringRef keyLabel = CFStringCreateWithCString (NULL, 
                                                      keyName.c_str (), 
                                                      keyName.size ());
    
    CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL,
                                                             3,
                                                             &kCFTypeDictionaryKeyCallBacks,
                                                             NULL);

    CFDictionaryAddValue(attrDict, kSecAttrKeyType, getKeyType(keyType));
    CFDictionaryAddValue(attrDict, kSecAttrKeySizeInBits, CFNumberCreate (NULL, kCFNumberIntType, &keySize));
    CFDictionaryAddValue(attrDict, kSecAttrLabel, keyLabel);

    OSStatus res = SecKeyGeneratePair ((CFDictionaryRef)attrDict, &publicKey, &privateKey);

    CFRelease (publicKey);
    CFRelease (privateKey);

    if (res != errSecSuccess){
      _LOG_DEBUG ("Fail to create a key pair: " << res);
      return false;
    }
    return true;
  }

  bool OSXPrivatekeyStore::generateKey(const string & keyName, KeyType keyType, int keySize)
  {
    return false;
  }

  Ptr<Publickey> OSXPrivatekeyStore::getPublickey(const string & keyName)
  {
    _LOG_TRACE("OSXPrivatekeyStore::getPublickey");

    SecKeychainItemRef publicKey = getKey(keyName, KEY_CLASS_PUBLIC);

    CFDataRef exportedKey;

    OSStatus res = SecItemExport (publicKey,
                                  kSecFormatOpenSSL,
                                  0,
                                  NULL,
                                  &exportedKey);
    
    Blob blob(CFDataGetBytePtr(exportedKey), CFDataGetLength(exportedKey));

    return Ptr<Publickey>(new Publickey(blob));
  }

  Ptr<Blob> OSXPrivatekeyStore::sign(const Blob & pData, const string & keyName, DigestAlgorithm digestAlgo)
  {
    _LOG_TRACE("OSXPrivatekeyStore::Sign");
    
    CFDataRef dataRef = CFDataCreate (NULL,
                                      reinterpret_cast<const unsigned char*>(pData.buf()),
                                      pData.size()
                                      );

    SecKeyRef privateKey = (SecKeyRef)getKey(keyName, KEY_CLASS_PRIVATE);
    
    CFErrorRef error;
    SecTransformRef signer = SecSignTransformCreate((SecKeyRef)privateKey, &error);
    if (error) throw SecException("Fail to create signer");
    
    Boolean set_res = SecTransformSetAttribute(signer,
                                               kSecTransformInputAttributeName,
                                               dataRef,
                                               &error);
    if (error) throw SecException("Fail to configure input of signer");

    set_res = SecTransformSetAttribute(signer,
                                       kSecDigestTypeAttribute,
                                       getDigestAlgorithm(digestAlgo),
                                       &error);
    if (error) throw SecException("Fail to configure digest algorithm of signer");

    long digestSize = getDigestSize(digestAlgo);

    set_res = SecTransformSetAttribute(signer,
                                       kSecDigestLengthAttribute,
                                       CFNumberCreate (NULL, kCFNumberLongType, &digestSize),
                                       &error);
    if (error) throw SecException("Fail to configure digest size of signer");

    CFDataRef signature = (CFDataRef) SecTransformExecute(signer, &error);
    if (error) {
      CFShow(error);
      throw SecException("Fail to sign data");
    }

    if (!signature) throw SecException("Signature is NULL!\n");

    Ptr<Blob> sigPtr = Ptr<Blob>(new Blob(CFDataGetBytePtr(signature), CFDataGetLength(signature)));

    return sigPtr;
  }

  Ptr<Blob> OSXPrivatekeyStore::decrypt(const string & keyName, const Blob & pData)
  {
    _LOG_TRACE("OSXPrivatekeyStore::Decrypt");
    
    CFDataRef dataRef = CFDataCreate (NULL,
                                      reinterpret_cast<const unsigned char*>(pData.buf()),
                                      pData.size()
                                      );
    
    SecKeyRef privateKey = (SecKeyRef)getKey(keyName, KEY_CLASS_PRIVATE);

    CFErrorRef error;
    SecTransformRef decrypt = SecDecryptTransformCreate((SecKeyRef)privateKey, &error);
    if (error) throw SecException("Fail to create decrypt");

    Boolean set_res = SecTransformSetAttribute(decrypt,
                                               kSecTransformInputAttributeName,
                                               dataRef,
                                               &error);
    if (error) throw SecException("Fail to configure decrypt");

    CFDataRef output = (CFDataRef) SecTransformExecute(decrypt, &error);
    if (error) throw SecException("Fail to decrypt data");

    if (!output) throw SecException("Output is NULL!\n");

    Ptr<Blob> outputPtr = Ptr<Blob>(new Blob(CFDataGetBytePtr(output), CFDataGetLength(output)));

    return outputPtr;

  }

  bool OSXPrivatekeyStore::setACL(const string & keyName, KeyClass keyClass, int acl, const string & appPath)
  {
    SecKeychainItemRef privateKey = getKey(keyName, keyClass);
    
    SecAccessRef accRef;
    OSStatus acc_res = SecKeychainItemCopyAccess (privateKey, &accRef);

    CFArrayRef signACL = SecAccessCopyMatchingACLList (accRef,
                                                       kSecACLAuthorizationSign);

    SecACLRef aclRef = (SecACLRef) CFArrayGetValueAtIndex(signACL, 0);

    CFArrayRef appList;
    CFStringRef description;
    SecKeychainPromptSelector promptSelector;
    OSStatus acl_res = SecACLCopyContents (aclRef,
                                           &appList,
                                           &description,
                                           &promptSelector);

    CFMutableArrayRef newAppList = CFArrayCreateMutableCopy(NULL,
                                                            0,
                                                            appList);

    SecTrustedApplicationRef trustedApp;
    acl_res = SecTrustedApplicationCreateFromPath (appPath.c_str(),
                                                   &trustedApp);
    
    CFArrayAppendValue(newAppList, trustedApp);


    CFArrayRef authList = SecACLCopyAuthorizations (aclRef);
    
    acl_res = SecACLRemove(aclRef);

    SecACLRef newACL;
    acl_res = SecACLCreateWithSimpleContents (accRef,
                                              newAppList,
                                              description,
                                              promptSelector,
                                              &newACL);

    acl_res = SecACLUpdateAuthorizations (newACL, authList);

    acc_res = SecKeychainItemSetAccess(privateKey, accRef);

    return true;
  }

  bool OSXPrivatekeyStore::verifyData (const string & keyName, const Blob & pData, const Blob & pSig, DigestAlgorithm digestAlgo)
  {
    _LOG_TRACE("OSXPrivatekeyStore::Verify");
    
    CFDataRef dataRef = CFDataCreate (NULL,
                                      reinterpret_cast<const unsigned char*>(pData.buf()),
                                      pData.size());

    CFDataRef sigRef = CFDataCreate (NULL,
                                     reinterpret_cast<const unsigned char*>(pSig.buf()),
                                     pSig.size());

    SecKeyRef publicKey = (SecKeyRef)getKey(keyName, KEY_CLASS_PUBLIC);
    
    CFErrorRef error;
    SecTransformRef verifier = SecVerifyTransformCreate(publicKey, sigRef, &error);
    if (error) throw SecException("Fail to create verifier");
    
    Boolean set_res = SecTransformSetAttribute(verifier,
                                               kSecTransformInputAttributeName,
                                               dataRef,
                                               &error);
    if (error) throw SecException("Fail to configure input of verifier");

    set_res = SecTransformSetAttribute(verifier,
                                       kSecDigestTypeAttribute,
                                       getDigestAlgorithm(digestAlgo),
                                       &error);
    if (error) throw SecException("Fail to configure digest algorithm of verifier");

    long digestSize = getDigestSize(digestAlgo);
    set_res = SecTransformSetAttribute(verifier,
                                       kSecDigestLengthAttribute,
                                       CFNumberCreate (NULL, kCFNumberLongType, &digestSize),
                                       &error);
    if (error) throw SecException("Fail to configure digest size of verifier");

    CFBooleanRef result = (CFBooleanRef) SecTransformExecute(verifier, &error);
    if (error) throw SecException("Fail to verify data");

    if (result == kCFBooleanTrue)
      return true;
    else
      return false;
  }

  Ptr<Blob> OSXPrivatekeyStore::encrypt(const string & keyName, const Blob & pData)
  {
    _LOG_TRACE("OSXPrivatekeyStore::Encrypt");
    
    CFDataRef dataRef = CFDataCreate (NULL,
                                      reinterpret_cast<const unsigned char*>(pData.buf()),
                                      pData.size()
                                      );
    
    SecKeyRef publicKey = (SecKeyRef)getKey(keyName, KEY_CLASS_PUBLIC);

    CFErrorRef error;
    SecTransformRef encrypt = SecEncryptTransformCreate(publicKey, &error);
    if (error) throw SecException("Fail to create encrypt");

    Boolean set_res = SecTransformSetAttribute(encrypt,
                                               kSecTransformInputAttributeName,
                                               dataRef,
                                               &error);
    if (error) throw SecException("Fail to configure encrypt");

    CFDataRef output = (CFDataRef) SecTransformExecute(encrypt, &error);
    if (error) throw SecException("Fail to encrypt data");

    if (!output) throw SecException("Output is NULL!\n");

    Ptr<Blob> outputPtr = Ptr<Blob>(new Blob(CFDataGetBytePtr(output), CFDataGetLength(output)));

    return outputPtr;
  }

  bool OSXPrivatekeyStore::doesNameExist(string keyName, KeyClass keyClass)
  {
    _LOG_TRACE("OSXPrivatekeyStore::NameUsed");

    CFStringRef keyLabel = CFStringCreateWithCString (NULL, 
                                                      keyName.c_str (), 
                                                      keyName.size ());
    
    CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL,
                                                                3,
                                                                &kCFTypeDictionaryKeyCallBacks,
                                                                NULL);

    CFDictionaryAddValue(attrDict, kSecAttrKeyClass, getKeyClass(keyClass));
    CFDictionaryAddValue(attrDict, kSecAttrLabel, keyLabel);
    CFDictionaryAddValue(attrDict, kSecReturnRef, kCFBooleanTrue);
    
    SecKeychainItemRef itemRef;
    OSStatus res = SecItemCopyMatching((CFDictionaryRef)attrDict, (CFTypeRef*)&itemRef);
    
    if(res == errSecItemNotFound)
      return true;
    else
      return false;

  }

  SecKeychainItemRef OSXPrivatekeyStore::getKey(string keyName, KeyClass keyClass)
  {
    CFStringRef keyLabel = CFStringCreateWithCString (NULL, 
                                                      keyName.c_str (), 
                                                      keyName.size ());
    
    CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL,
                                                             5,
                                                             &kCFTypeDictionaryKeyCallBacks,
                                                             NULL);

    CFDictionaryAddValue(attrDict, kSecClass, kSecClassKey);
    CFDictionaryAddValue(attrDict, kSecAttrLabel, keyLabel);
    CFDictionaryAddValue(attrDict, kSecAttrKeyClass, getKeyClass(keyClass));
    CFDictionaryAddValue(attrDict, kSecReturnRef, kCFBooleanTrue);
    
    SecKeychainItemRef keyItem;

    OSStatus res = SecItemCopyMatching((CFDictionaryRef) attrDict, (CFTypeRef*)&keyItem);
    
    if(res != errSecSuccess){
      _LOG_DEBUG("Fail to find the key!");
      return NULL;
    }
    else
      return keyItem;
  }

  const CFTypeRef OSXPrivatekeyStore::getKeyType(KeyType keyType)
  {
    switch(keyType){
    case KEY_TYPE_RSA:
      return kSecAttrKeyTypeRSA;
    default:
      _LOG_DEBUG("Unrecognized key type!")
      return NULL;
    }
  }

  const CFTypeRef OSXPrivatekeyStore::getKeyClass(KeyClass keyClass)
  {
    switch(keyClass){
    case KEY_CLASS_PRIVATE:
      return kSecAttrKeyClassPrivate;
    case KEY_CLASS_PUBLIC:
      return kSecAttrKeyClassPublic;
    case KEY_CLASS_SYMMETRIC:
      return kSecAttrKeyClassSymmetric;
    default:
      _LOG_DEBUG("Unrecognized key class!");
      return NULL;
    }
  }

  SecExternalFormat OSXPrivatekeyStore::getFormat(KeyFormat format)
  {
    switch(format){
    case KEY_PUBLIC_OPENSSL:
      return kSecFormatOpenSSL;
    default:
      _LOG_DEBUG("Unrecognized output format!");
      return 0;
    }
  }

  const CFStringRef OSXPrivatekeyStore::getDigestAlgorithm(DigestAlgorithm digestAlgo)
  {
    switch(digestAlgo){
    case DIGEST_MD2:
      return kSecDigestMD2;
    case DIGEST_MD5:
      return kSecDigestMD5;
    case DIGEST_SHA1:
      return kSecDigestSHA1;
    case DIGEST_SHA256:
      return kSecDigestSHA2;
    default:
      _LOG_DEBUG("Unrecognized digest algorithm!");
      return NULL;
    }
  }

  long OSXPrivatekeyStore::getDigestSize(DigestAlgorithm digestAlgo)
  {
    switch(digestAlgo){
    case DIGEST_SHA256:
      return 256;
    case DIGEST_SHA1:
    case DIGEST_MD2:
    case DIGEST_MD5:
      return 0;
    default:
      _LOG_DEBUG("Unrecognized digest algorithm! Unknown digest size");
      return -1;
    }
  }

  
}//security

}//ndn
