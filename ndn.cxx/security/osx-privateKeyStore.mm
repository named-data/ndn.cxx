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
#include "ndn.cxx/security/certificate/der.h"
#include "ndn.cxx/wire/ccnb.h"

#include <fstream>
#include <sstream>

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

  bool OSXPrivateKeyStore::ExportPublicKey(string keyName, KeyType keyType, KeyFormat keyFormat, string outputDir, bool pem)
  {
    _LOG_TRACE("OSXPrivateKeyStore::ExportPublicKey");

    SecKeychainItemRef publicKey = FetchKey(keyName, keyType, KEY_CLASS_PUBLIC);

    CFDataRef exportedKey;

    // SecKeyImportExportParameters param;
    // param.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    // param.flags = kSecItemPemArmour;

    SecItemImportExportFlags pemFlag = NULL;
    if(pem)
      pemFlag = kSecItemPemArmour;

    OSStatus res = SecItemExport (publicKey,
                                  GetFormat(keyFormat),
                                  pemFlag,
                                  NULL,
                                  &exportedKey);
    
    _LOG_DEBUG("getPublicKey: " << res);
    
    string output((const char*)(CFDataGetBytePtr(exportedKey)), CFDataGetLength(exportedKey));
    cout << output << endl;
    
    ofstream f (outputDir.c_str());
    
    f.write((const char*)(CFDataGetBytePtr(exportedKey)), CFDataGetLength(exportedKey));
    

    return false;
  }

  Ptr<Blob> OSXPrivateKeyStore::GetPublicKey(string keyName, KeyType keyType, KeyFormat keyFormat, bool pem)
  {
    //TODO::
    return NULL;
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
    if (error) throw SecException("Fail to configure input of signer");

    set_res = SecTransformSetAttribute(signer,
                                       kSecDigestTypeAttribute,
                                       GetDigestAlgorithm(digestAlgo),
                                       &error);
    if (error) throw SecException("Fail to configure digest algorithm of signer");

    long digestSize = GetDigestSize(digestAlgo);

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

  Ptr<Blob> OSXPrivateKeyStore::SignData(const Data & data, string keyName, KeyType keyType, DigestAlgorithm digestAlgo)
  {
    stringstream ss;
    
    // Ccnb::appendName(ss, data.getName ()); // <Name>

    // Ccnb::appendBlockHeader(ss, Ccnb::CCN_DTAG_SignedInfo, Ccnb::CCN_DTAG); // <SignedInfo>
    // Ccnb::appendTaggedBlob(ss, Ccnb::CCN_DTAG_PublisherPublicKeyDigest, *(PublicKeyDigest(keyName, keyType, KEY_PUBLIC_OPENSSL, digestAlgo)));
    // Ccnb::appendTimestampBlob(ss, data.getContent ().getTimestamp ());
    // Ccnb::appendTaggedBlob (ss, Ccnb::CCN_DTAG_Type, TYPES [data.getContent ().getType ()], 3);
    
    // if (data.getContent ().getFreshness () != Content::noFreshness){
    //   Ccnb::appendTaggedNumber (ss, Ccnb::CCN_DTAG_FreshnessSeconds,
    //                             data.getContent ().getFreshness ().total_seconds ());
    // }

    // if (data.getContent ().getFinalBlockId () != Content::noFinalBlock){
    //   Ccnb::appendTaggedBlob (ss, Ccnb::CCN_DTAG_FinalBlockID, data.getContent ().getFinalBlockId ());
    // }

    // Ccnb::appendBlockHeader (ss, Ccnb::CCN_DTAG_KeyLocator, Ccnb::CCN_DTAG); // <KeyLocator>
    // switch (signature.getKeyLocator ().getType ()){
    // case KeyLocator::NOTSET:
    //   break;
    // case KeyLocator::KEY:
    //   Ccnb::appendTaggedBlob (ss, Ccnb::CCN_DTAG_Key, signature.getKeyLocator ().getKey ());
    //   break;
    // case KeyLocator::CERTIFICATE:
    //   Ccnb::appendTaggedBlob (ss, Ccnb::CCN_DTAG_Certificate, signature.getKeyLocator ().getCertificate ());
    //   break;
    // case KeyLocator::KEYNAME:
    //   Ccnb::appendBlockHeader (ss, Ccnb::CCN_DTAG_KeyName, Ccnb::CCN_DTAG); // <KeyName>
    //   Ccnb::appendName (ss, signature.getKeyLocator ().getKeyName ());
    //   Ccnb::appendCloser (ss); // </KeyName>
    //   break;
    // }
    // Ccnb::appendCloser (ss); // </KeyLocator>
    
    // Ccnb::appendCloser (ss); // </SignedInfo>

    // Ccnb::appendTaggedBlob (ss, Ccnb::CCN_DTAG_Content, data.content ()); // <Content>
    

    //TODO:
    return NULL;
  }

  Ptr<Blob> OSXPrivateKeyStore::PublicKeyDigest(string keyName, KeyType keyType, KeyFormat keyFormat, DigestAlgorithm digestAlgo)
  {
    CFErrorRef error = NULL;

    SecTransformRef digester = SecDigestTransformCreate(GetDigestAlgorithm(digestAlgo),
                                                        GetDigestSize(digestAlgo),
                                                        &error);
    
    if(error) throw SecException("Fail to create digest");

    SecKeychainItemRef publicKey = FetchKey(keyName, keyType, KEY_CLASS_PUBLIC);

    CFDataRef exportedKey;

    OSStatus res = SecItemExport (publicKey,
                                  GetFormat(keyFormat),
                                  NULL,
                                  NULL,
                                  &exportedKey);
    
    _LOG_DEBUG("getPublicKey: " << res);

    Boolean set_res = SecTransformSetAttribute(digester,
                                               kSecTransformInputAttributeName,
                                               exportedKey,
                                               &error);
    
    if (error) throw SecException("Fail to configure input of digester");
    
    CFDataRef keyDigest = (CFDataRef) SecTransformExecute(digester, &error);
    
    if (error) throw SecException("Fail to digest data");
    
    return Ptr<Blob>(new Blob(CFDataGetBytePtr(keyDigest), CFDataGetLength(keyDigest)));
  }

  void OSXPrivateKeyStore::TestDigest(){
    CFErrorRef error = NULL;

    SecTransformRef digester = SecDigestTransformCreate(kSecDigestSHA2,
                                                        256,
                                                        &error);

    
    if(error) throw SecException("Fail to create digest");

    string str = "testDataTestData";
    CFDataRef dataRef = CFDataCreate (NULL,
                                      reinterpret_cast<const unsigned char*>(str.c_str()),
                                      str.size());

    Boolean set_res = SecTransformSetAttribute(digester,
                                               kSecTransformInputAttributeName,
                                               dataRef,
                                               &error);

    // long tmpSize = 32;
    // set_res = SecTransformSetAttribute(digester,
    //                                    kSecDigestLengthAttribute,
    //                                    CFNumberCreate (NULL, kCFNumberLongType, &tmpSize),
    //                                    &error);

    CFNumberRef digestSize = (CFNumberRef) SecTransformGetAttribute(digester,
                                                                    kSecDigestLengthAttribute); 

    long dSize = 0;

    CFNumberGetValue (digestSize,
                      kCFNumberLongType,
                      &dSize);

    _LOG_DEBUG("dSize: " << dSize);


    if (error) throw SecException("Fail to configure encrypt");
    
    CFDataRef output = (CFDataRef) SecTransformExecute(digester, &error);
    
    if (error) throw SecException("Fail to digest data");

    
    Ptr<Blob> outputPtr = Ptr<Blob>(new Blob(CFDataGetBytePtr(output), CFDataGetLength(output)));

    DERendec endec;
    
    endec.PrintBlob(*outputPtr, "");
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
    if (error) throw SecException("Fail to configure input of verifier");

    set_res = SecTransformSetAttribute(verifier,
                                       kSecDigestTypeAttribute,
                                       GetDigestAlgorithm(digestAlgo),
                                       &error);
    if (error) throw SecException("Fail to configure digest algorithm of verifier");

    long digestSize = GetDigestSize(digestAlgo);
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
    case KEY_PUBLIC_OPENSSL:
      return kSecFormatOpenSSL;
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
    case DIGEST_SHA256:
      return kSecDigestSHA2;
    default:
      _LOG_DEBUG("Unrecognized digest algorithm!");
      return NULL;
    }
  }

  long OSXPrivateKeyStore::GetDigestSize(DigestAlgorithm digestAlgo)
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
