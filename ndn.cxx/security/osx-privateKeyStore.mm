/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <CoreFoundation/CoreFoundation.h>

#include "ndn.cxx/security/osx-privateKeyStore.h"

#include <fstream>

#include "logging.h"

using namespace std;
using namespace ndn;

INIT_LOGGER ("OSXPrivateKeyStore");

namespace ndn
{

namespace security
{

  OSXPrivateKeyStore::OSXPrivateKeyStore(string keychainName)
    : m_keychainName("" == keychainName ?  "NDN.keychain" : keychainName)
  {
    _LOG_TRACE ("OSXPrivateKeyStore Constructor");
   
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

  OSXPrivateKeyStore::~OSXPrivateKeyStore (){
    //TODO: implement
  }

  bool OSXPrivateKeyStore::GenerateKeyPair(string keyName, KeyType keyType, int keySize)
  {
    _LOG_TRACE("OSXPrivateKeyStore::GenerateKeyPair");
    
    if(NameExists(keyName, KEY_CLASS_PRIVATE)){
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

    CFDictionaryAddValue(attrDict, kSecAttrKeyType, GetKeyType(keyType));
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

  bool OSXPrivateKeyStore::GenerateKey(string keyName, KeyType keyType, int keySize)
  {
    return false;
  }

  bool OSXPrivateKeyStore::ExportPublicKey(string keyName, KeyType keyType, KeyFormat keyFormat, string outputDir)
  {
    _LOG_TRACE("OSXPrivateKeyStore::ExportPublicKey");

    SecKeychainItemRef publicKey = FetchKey(keyName, keyType, KEY_CLASS_PUBLIC);

    CFDataRef exportedKey;

    SecKeyImportExportParameters param;
    param.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    param.flags = kSecItemPemArmour;
    
    OSStatus res = SecItemExport (publicKey,
                                  kSecFormatOpenSSL,
                                  NULL,
                                  NULL,
                                  &exportedKey);
    
    _LOG_DEBUG("getPrivateKey: " << res);
    
    string output((const char*)(CFDataGetBytePtr(exportedKey)), CFDataGetLength(exportedKey));
    cout << output << endl;
    
    ofstream f ("out1.pub");
    
    f.write((const char*)(CFDataGetBytePtr(exportedKey)), CFDataGetLength(exportedKey));
    

    return false;
  }

  Ptr<Blob> OSXPrivateKeyStore::Sign(string keyName, KeyType keyType, DigestAlgorithm digestAlgo, Ptr<Blob> pData)
  {
    _LOG_TRACE("OSXPrivateKeyStore::Sign");
    
    CFDataRef dataRef = CFDataCreate (NULL,
                                      reinterpret_cast<const unsigned char*>(pData->buf()),
                                      pData->size()
                                      );

    SecKeyRef privateKey = (SecKeyRef)FetchKey(keyName, keyType, KEY_CLASS_PRIVATE);
    
    CFErrorRef error;
    SecTransformRef signer = SecSignTransformCreate((SecKeyRef)privateKey, &error);
    if (error) throw SecException("Fail to create signer");
    
    Boolean set_res = SecTransformSetAttribute(signer,
                                               kSecTransformInputAttributeName,
                                               dataRef,
                                               &error);
    if (error) throw SecException("Fail to configure signer");

    set_res = SecTransformSetAttribute(signer,
                                       kSecDigestTypeAttribute,
                                       GetDigestAlgorithm(digestAlgo),
                                       &error);
    if (error) throw SecException("Fail to configure signer");

    CFDataRef signature = (CFDataRef) SecTransformExecute(signer, &error);
    if (error) throw SecException("Fail to sign data");

    if (!signature) throw SecException("Signature is NULL!\n");
    

    Ptr<Blob> sigPtr = Ptr<Blob>(new Blob(CFDataGetBytePtr(signature), CFDataGetLength(signature)));

    return sigPtr;
  }

  Ptr<Blob> OSXPrivateKeyStore::Decrypt(string keyName, Ptr<Blob> pData)
  {
    _LOG_TRACE("OSXPrivateKeyStore::Decrypt");
    
    CFDataRef dataRef = CFDataCreate (NULL,
                                      reinterpret_cast<const unsigned char*>(pData->buf()),
                                      pData->size()
                                      );
    
    SecKeyRef privateKey = (SecKeyRef)FetchKey(keyName, KEY_TYPE_RSA, KEY_CLASS_PRIVATE);

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

  bool OSXPrivateKeyStore::SetACL(string keyName, KeyType keyType, KeyClass keyClass, int acl, string appPath)
  {
    SecKeychainItemRef privateKey = FetchKey(keyName, keyType, keyClass);
    
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


  bool OSXPrivateKeyStore::Verify(string keyName, KeyType keyType, DigestAlgorithm digestAlgo, Ptr<Blob> pData, Ptr<Blob>pSig)
  {
    _LOG_TRACE("OSXPrivateKeyStore::Verify");
    
    CFDataRef dataRef = CFDataCreate (NULL,
                                      reinterpret_cast<const unsigned char*>(pData->buf()),
                                      pData->size());

    CFDataRef sigRef = CFDataCreate (NULL,
                                     reinterpret_cast<const unsigned char*>(pSig->buf()),
                                     pSig->size());

    SecKeyRef publicKey = (SecKeyRef)FetchKey(keyName, KEY_TYPE_RSA, KEY_CLASS_PUBLIC);
    
    CFErrorRef error;
    SecTransformRef verifier = SecVerifyTransformCreate(publicKey, sigRef, &error);
    if (error) throw SecException("Fail to create verifier");
    
    Boolean set_res = SecTransformSetAttribute(verifier,
                                               kSecTransformInputAttributeName,
                                               dataRef,
                                               &error);
    if (error) throw SecException("Fail to configure verifier");

    set_res = SecTransformSetAttribute(verifier,
                                       kSecDigestTypeAttribute,
                                       GetDigestAlgorithm(digestAlgo),
                                       &error);
    if (error) throw SecException("Fail to configure signer");

    CFBooleanRef result = (CFBooleanRef) SecTransformExecute(verifier, &error);
    if (error) throw SecException("Fail to verify data");

    if (result == kCFBooleanTrue)
      return true;
    else
      return false;
  }

  Ptr<Blob> OSXPrivateKeyStore::Encrypt(string keyName, Ptr<Blob> pData)
  {
    _LOG_TRACE("OSXPrivateKeyStore::Encrypt");
    
    CFDataRef dataRef = CFDataCreate (NULL,
                                      reinterpret_cast<const unsigned char*>(pData->buf()),
                                      pData->size()
                                      );
    
    SecKeyRef publicKey = (SecKeyRef)FetchKey(keyName, KEY_TYPE_RSA, KEY_CLASS_PUBLIC);

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

  bool OSXPrivateKeyStore::NameExists(string keyName, KeyClass keyClass)
  {
    _LOG_TRACE("OSXPrivateKeyStore::NameUsed");

    CFStringRef keyLabel = CFStringCreateWithCString (NULL, 
                                                      keyName.c_str (), 
                                                      keyName.size ());
    
    CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL,
                                                                3,
                                                                &kCFTypeDictionaryKeyCallBacks,
                                                                NULL);

    CFDictionaryAddValue(attrDict, kSecAttrKeyClass, GetKeyClass(keyClass));
    CFDictionaryAddValue(attrDict, kSecAttrLabel, keyLabel);
    CFDictionaryAddValue(attrDict, kSecReturnRef, kCFBooleanTrue);
    
    SecKeychainItemRef itemRef;
    OSStatus res = SecItemCopyMatching((CFDictionaryRef)attrDict, (CFTypeRef*)&itemRef);
    
    if(res == errSecItemNotFound)
      return true;
    else
      return false;

  }

  SecKeychainItemRef OSXPrivateKeyStore::FetchKey(string keyName, KeyType keyType, KeyClass keyClass)
  {
    CFStringRef keyLabel = CFStringCreateWithCString (NULL, 
                                                      keyName.c_str (), 
                                                      keyName.size ());
    
    CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL,
                                                             5,
                                                             &kCFTypeDictionaryKeyCallBacks,
                                                             NULL);

    CFDictionaryAddValue(attrDict, kSecClass, kSecClassKey);
    CFDictionaryAddValue(attrDict, kSecAttrKeyType, GetKeyType(keyType));
    CFDictionaryAddValue(attrDict, kSecAttrLabel, keyLabel);
    CFDictionaryAddValue(attrDict, kSecAttrKeyClass, GetKeyClass(keyClass));
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

  const CFTypeRef OSXPrivateKeyStore::GetKeyType(KeyType keyType)
  {
    switch(keyType){
    case KEY_TYPE_RSA:
      return kSecAttrKeyTypeRSA;
    default:
      _LOG_DEBUG("Unrecognized key type!")
      return NULL;
    }
  }

  const CFTypeRef OSXPrivateKeyStore::GetKeyClass(KeyClass keyClass)
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

  SecExternalFormat OSXPrivateKeyStore::GetFormat(KeyFormat format)
  {
    switch(format){
    case KEY_X509:
      return kSecFormatX509Cert;
    default:
      _LOG_DEBUG("Unrecognized output format!");
      return NULL;
    }
  }

  const CFStringRef OSXPrivateKeyStore::GetDigestAlgorithm(DigestAlgorithm digestAlgo)
  {
    switch(digestAlgo){
    case DIGEST_MD2:
      return kSecDigestMD2;
    case DIGEST_MD5:
      return kSecDigestMD5;
    case DIGEST_SHA1:
      return kSecDigestSHA1;
    default:
      _LOG_DEBUG("Unrecognized algorithm!");
      return NULL;
    }
  }

  
}//security

}//ndn
