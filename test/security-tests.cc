/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *                     Zhenkai Zhu
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 *         Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <boost/test/unit_test.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/regex/regex.h"

#include "ndn.cxx/security/keychain.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/security/certificate/publickey.h"
#include "ndn.cxx/security/certificate/certificate-subdescrpt.h"
#include "ndn.cxx/security/policy/identity-policy-rule.h"
#include "ndn.cxx/security/policy/basic-policy-manager.h"
#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/identity/basic-identity-storage.h"
#include "ndn.cxx/security/identity/osx-privatekey-storage.h"
#include "ndn.cxx/security/encryption/aes-cipher.h"
#include "ndn.cxx/security/encryption/basic-encryption-manager.h"
#include "ndn.cxx/security/cache/basic-certificate-cache.h"

#include "ndn.cxx/helpers/der/der.h"
#include "ndn.cxx/helpers/der/visitor/print-visitor.h"

#include "ndn.cxx/security/tmp/dump-certificate.h"

#include "ndn.cxx/fields/signature-sha256-with-rsa.h"


#include <iostream>
#include <fstream>
#include <sstream>
#include <cryptopp/rsa.h>

using namespace std;
using namespace ndn;
using namespace ndn::security;


BOOST_AUTO_TEST_SUITE(SecurityTests)

Ptr<Data> generateCertificate(Name keyName, Ptr<security::Publickey> pubKey)
{
  Ptr<Certificate> certificate = Create<Certificate>();
  
  Name certificateName;
  certificateName.append(keyName).append("ID-CERT").append("0");
  certificate->setName(certificateName);

  tm current = boost::posix_time::to_tm(time::Now());
  current.tm_hour = 0;
  current.tm_min  = 0;
  current.tm_sec  = 0;
  Time notBefore = boost::posix_time::ptime_from_tm(current);
  current.tm_year = current.tm_year + 20;
  Time notAfter = boost::posix_time::ptime_from_tm(current);
  certificate->setNotBefore(notBefore);
  certificate->setNotAfter(notBefore);
  certificate->setPublicKeyInfo(*pubKey);
  certificate->addSubjectDescription(security::CertificateSubDescrypt("2.5.4.41", keyName.toUri()));

  certificate->encode();
  
  return certificate;
}

BOOST_AUTO_TEST_CASE (Basic)
{
  string keyName = "/ndn/ucla/yingdi";
  security::OSXPrivatekeyStorage keystore;
  //  keystore.GenerateKeyPair(keyName);
  
  string testData = "testDataTestData";
  Ptr<Blob> pTestData = Ptr<Blob>(new Blob(testData.c_str(), testData.size()));
  try{
    Ptr<Blob> pSig = keystore.sign(*pTestData, keyName, security::DIGEST_SHA256);
    
    ofstream os("sig.sig");
    os.write(pSig->buf(), pSig->size());
    cerr << pSig->size()<< endl;
  
    //    cout << boolalpha << keystore.verify(keyName, security::KEY_TYPE_RSA, security::DIGEST_SHA256, pTestData, pSig) << endl;

    Ptr<Blob> pEncrypt = keystore.encrypt(keyName, *pTestData);
    Ptr<Blob> pDecrypt = keystore.decrypt(keyName, *pEncrypt);

    string output(pDecrypt->buf(), pDecrypt->size());
    cout << output << endl;
  }catch (security::SecException & e){
    cerr << e.Msg() << endl;
  }

}

BOOST_AUTO_TEST_CASE (Digest)
{
  // string keyName = "/ndn/ucla/yingdi";
  // security::DERendec endec;

  // security::OSXPrivatekeyStorage keystore;
  // try{
  //   Data data;
  //   // //.../DNS/.../zsk-seq#(for key)/NDNCERT/certSeq#(for certificate)
  //   // Name name = Name("/ndn/ucla/DNS/yingdi/zsk-1/NDNCERT/20130722");

  //   // data.setName(name);
    
  //   // Ptr<Blob> keyPtr = readKey("out1.pub");
  //   // Content content;
  //   // content.setContent(*keyPtr);
  //   // content.setTimeStamp();
  //   // content.setType(Content::KEY);
    
  //   // data.setContent(content);
    
  //   // Signature sig;
  //   // KeyLocator keyLocator;
  //   // keyLocator.setType(KeyLocator::KEYNAME);
  //   // keyLocator.setKeyName(name);

  //   // data.setSignature(sig);
    

  //   // endec.PrintBlob(keystore.PublicKeyDigest(keyName, security::KEY_TYPE_RSA, security::KEY_PUBLIC_OPENSSL, security::DIGEST_SHA256), "");
  // }catch (security::SecException & e){
  //   cerr << e.Msg() << endl;
  // }

}

BOOST_AUTO_TEST_CASE (IdentityPolicyTest)
{
  security::IdentityPolicyRule policy("^(<>*)<DNS>(<>*)$", "^(<>*)<DNS>(<>*)<><NDNCERT>", ">=", "\\1\\2", "\\1\\2", true);
  ostringstream oss;
  oss << *policy.toXmlElement();

  cout << oss.str() << endl;

  security::IdentityPolicyRule::fromXmlElement(policy.toXmlElement());

  
}

BOOST_AUTO_TEST_CASE (WireFormat)
{
  // using namespace boost::posix_time;

  // Data data;

  // data.setName(Name("/ndn/ucla.edu/cs/yingdi/"));
  
  // string contentStr = "hello, world!";
  
  // Content content(contentStr.c_str(), 
  //                 contentStr.size(),
  //                 second_clock::universal_time());

  // data.setContent(content);

  // Sha256WithRsa signature;

}

BOOST_AUTO_TEST_CASE (IdentityStorageTest)
{
  try{
    security::BasicIdentityStorage idStore;

    Ptr<Data> dataPtr = idStore.getCertificate (Name("/ndn/ucla.edu/qiuhan/KSK-1378422677/ID-CERT/1378423300"), true);
    
    boost::iostreams::stream
      <boost::iostreams::array_source> is (dataPtr->content().buf(), dataPtr->content().size());
    
    Ptr<der::DerNode> node = der::DerNode::parse(reinterpret_cast<InputIterator &>(is));

    der::PrintVisitor printVisitor;
    node->accept(printVisitor, string(""));
  
    
    


    // cout << boolalpha << idStore.doesIdentityExist(Name("/ndn/ucla.edu/yingdi")) << endl;

    // Name keyName = idStore.getNewKeyName(Name("/ndn/ucla.edu/yingdi"), true);

    // string blobBits = "1234567890";
    // Ptr<Blob> blobPtr = Ptr<Blob>(new Blob(blobBits.c_str(), blobBits.size()));
    
    // // idStore.addKey(keyName, security::KEY_TYPE_DSA, blobPtr);

    // idStore.activateKey(Name("/ndn/ucla.edu/yingdi/KSK-1375992917"));

    // idStore.deactivateKey(Name("/ndn/ucla.edu/yingdi/KSK-1375992917"));

    // idStore.getAnyCertificate(Name("/ndn/edu/ucla/KSK-123456789/ID-CERT"));


  }catch(security::SecException & e){
    cerr << e.Msg();
  }
}

BOOST_AUTO_TEST_CASE (IdentityManagerTest)
{
  Ptr<security::BasicIdentityStorage> publicStorage = Ptr<security::BasicIdentityStorage>::Create();
  Ptr<security::OSXPrivatekeyStorage> privateStorage = Ptr<security::OSXPrivatekeyStorage>::Create();

  security::IdentityManager identityManager(publicStorage, privateStorage);

  Ptr<security::Publickey> signingRequest = NULL;
  identityManager.createIdentity(Name("/ndn"));


  Name ndn_DSK_Name = identityManager.generateRSAKeyPair(Name("/ndn"));
  signingRequest = identityManager.getPublickey(ndn_DSK_Name);
  Ptr<Data> ndn_DSK_unsign_cert = generateCertificate(ndn_DSK_Name, signingRequest);

  Name signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name("/ndn"));
  identityManager.signByCertificate(*ndn_DSK_unsign_cert, signingCertificateName);
  security::Certificate ndn_DSK_cert(*ndn_DSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_DSK_cert);

  identityManager.createIdentity(Name("/ndn/ucla.edu"));
  Name ndn_UCLA_KSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu"), true);


  signingRequest = identityManager.getPublickey(ndn_UCLA_KSK_name);
  Ptr<Data> ndn_UCLA_KSK_unsign_cert = generateCertificate(ndn_UCLA_KSK_name, signingRequest);

  signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name("/ndn"));
  identityManager.signByCertificate(*ndn_UCLA_KSK_unsign_cert, signingCertificateName);
  security::Certificate ndn_UCLA_KSK_cert(*ndn_UCLA_KSK_unsign_cert);


  identityManager.addCertificateAsIdentityDefault(ndn_UCLA_KSK_cert);

  Name ndn_UCLA_DSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu"));
  signingRequest = identityManager.getPublickey(ndn_UCLA_DSK_name);
  Ptr<Data> ndn_UCLA_DSK_unsign_cert = generateCertificate(ndn_UCLA_DSK_name, signingRequest);
  
  signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name("/ndn/ucla.edu"));
  identityManager.signByCertificate(*ndn_UCLA_DSK_unsign_cert, signingCertificateName);
  security::Certificate ndn_UCLA_DSK_cert(*ndn_UCLA_DSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_UCLA_DSK_cert);



  identityManager.createIdentity(Name("/ndn/ucla.edu/yingdi"));
  Name ndn_Yingdi_KSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu/yingdi"), true);


  signingRequest = identityManager.getPublickey(ndn_Yingdi_KSK_name);
  Ptr<Data> ndn_Yingdi_KSK_unsign_cert = generateCertificate(ndn_Yingdi_KSK_name, signingRequest);
  
  signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name("/ndn/ucla.edu"));
  identityManager.signByCertificate(*ndn_Yingdi_KSK_unsign_cert, signingCertificateName);
  security::Certificate ndn_Yingdi_KSK_cert(*ndn_Yingdi_KSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_Yingdi_KSK_cert);


  Name ndn_Yingdi_DSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu/yingdi"));
  signingRequest = identityManager.getPublickey(ndn_Yingdi_DSK_name);
  Ptr<Data> ndn_Yingdi_DSK_unsign_cert = generateCertificate(ndn_Yingdi_DSK_name, signingRequest);
  
  signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name("/ndn/ucla.edu/yingdi"));
  identityManager.signByCertificate(*ndn_Yingdi_DSK_unsign_cert, signingCertificateName);
  security::Certificate ndn_Yingdi_DSK_cert(*ndn_Yingdi_DSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_Yingdi_DSK_cert);

  

  identityManager.createIdentity(Name("/ndn/ucla.edu/yingdi/app"));
  Name ndn_APP_KSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu/yingdi/app"), true);


  signingRequest = identityManager.getPublickey(ndn_APP_KSK_name);
  Ptr<Data> ndn_APP_KSK_unsign_cert = generateCertificate(ndn_APP_KSK_name, signingRequest);

  signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name("/ndn/ucla.edu/yingdi"));
  identityManager.signByCertificate(*ndn_APP_KSK_unsign_cert, signingCertificateName);
  security::Certificate ndn_APP_KSK_cert(*ndn_APP_KSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_APP_KSK_cert);


  Name ndn_APP_DSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu/yingdi/app"));
  signingRequest = identityManager.getPublickey(ndn_APP_DSK_name);
  Ptr<Data> ndn_APP_DSK_unsign_cert = generateCertificate(ndn_APP_DSK_name, signingRequest);

  signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name("/ndn/ucla.edu/yingdi/app"));
  identityManager.signByCertificate(*ndn_APP_DSK_unsign_cert, signingCertificateName);
  security::Certificate ndn_APP_DSK_cert(*ndn_APP_DSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_APP_DSK_cert);
}

BOOST_AUTO_TEST_CASE (IdentityManagerSetDefault)
{
  Ptr<security::BasicIdentityStorage> publicStorage = Ptr<security::BasicIdentityStorage>::Create();
  Ptr<security::OSXPrivatekeyStorage> privateStorage = Ptr<security::OSXPrivatekeyStorage>::Create();

  security::IdentityManager identityManager(publicStorage, privateStorage);
  
  // identityManager.loadDefaultIdentity();
}

BOOST_AUTO_TEST_CASE(PrivateStoreTest)
{
  security::OSXPrivatekeyStorage privateStorage;
  try{
  string keyName = "/ndn/ucla.edu/yingdi/app/0";
  // privateStorage.generateKey(keyName);
  
  string data = "12345678901234567890123456789012345678901234567890";
  Blob blob = Blob(data.c_str(), data.size());

  Ptr<Blob> encrypted = privateStorage.encrypt(keyName, blob, true);
  Ptr<Blob> decrypted = privateStorage.decrypt(keyName, *encrypted, true);
  
  string output(decrypted->buf(), decrypted->size());
  cout << output << endl;
  }catch(security::SecException & e){
    cerr << e.Msg() << endl;
  }
}

BOOST_AUTO_TEST_CASE(PolicyManagerTest)
{
  Ptr<security::OSXPrivatekeyStorage> privateStoragePtr = Ptr<security::OSXPrivatekeyStorage>::Create();
  security::BasicIdentityStorage identityStorage;

  security::BasicPolicyManager policyManager("/Users/yuyingdi/Test/policy", privateStoragePtr);

  policyManager.setVerificationPolicyRule(Ptr<security::IdentityPolicyRule>(new security::IdentityPolicyRule("^(<>*)<KSK-.*><ID-CERT>", "^(<>*)<DSK-.*><ID-CERT>", "==", "\\1", "\\1", false)));
  policyManager.setVerificationPolicyRule(Ptr<security::IdentityPolicyRule>(new security::IdentityPolicyRule("^(<>*)<DSK-.*><ID-CERT>", "^(<>*)<KSK-.*><ID-CERT>", "==", "\\1", "\\1", true)));  
  policyManager.setVerificationPolicyRule(Ptr<security::IdentityPolicyRule>(new security::IdentityPolicyRule("^(<>*)<><KSK-.*><ID-CERT>", "^(<>*)<DSK-.*><ID-CERT>", ">=", "\\1", "\\1", true)));
  policyManager.setVerificationPolicyRule(Ptr<security::IdentityPolicyRule>(new security::IdentityPolicyRule("^(<>*)", "^(<>*)<DSK-.*><ID-CERT>", ">", "\\1", "\\1", true)));

  policyManager.setSigningPolicyRule(Ptr<security::IdentityPolicyRule>(new security::IdentityPolicyRule("^(<>*)<KSK-.*><ID-CERT>", "^(<>*)<DSK-.*><ID-CERT>", "==", "\\1", "\\1", false)));  
  policyManager.setSigningPolicyRule(Ptr<security::IdentityPolicyRule>(new security::IdentityPolicyRule("^(<>*)<DSK-.*><ID-CERT>", "^(<>*)<KSK-.*><ID-CERT>", "==", "\\1", "\\1", true))); 
  policyManager.setSigningPolicyRule(Ptr<security::IdentityPolicyRule>(new security::IdentityPolicyRule("^(<>*)<><KSK-.*><ID-CERT>", "^(<>*)<DSK-.*><ID-CERT>", ">=", "\\1", "\\1", true)));
  policyManager.setSigningPolicyRule(Ptr<security::IdentityPolicyRule>(new security::IdentityPolicyRule("^(<>*)", "^(<>*)<DSK-.*><ID-CERT>", ">", "\\1", "\\1", true)));


  ifstream is ("trust-anchor.data", ios::binary);

  is.seekg (0, ios::end);
  ifstream::pos_type size = is.tellg();
  char * memblock = new char [size];
    
  is.seekg (0, ios::beg);
  is.read (memblock, size);
  is.close();

  Ptr<Blob> readBlob = Ptr<Blob>(new Blob(memblock, size));

  Ptr<Data> readData = Data::decodeFromWire (readBlob);

  security::Certificate cert(*readData); 
  
  policyManager.setTrustAnchor(cert);

  cerr << "SavePolicy" << endl;
  
  policyManager.savePolicy();
  
}

BOOST_AUTO_TEST_CASE(DumpCert)
{ 
  security::BasicIdentityStorage identityStorage;

  Ptr<Data> data = identityStorage.getCertificate(Name("/ndn/KSK-1376698603/ID-CERT/0"), true);

  Ptr<Blob> dataBlob = data->encodeToWire();

  ofstream os ("trust-anchor.data", ios::binary); 

  os.write(dataBlob->buf(), dataBlob->size());

  os.close();

  ifstream is ("trust-anchor.data", ios::binary);

  is.seekg (0, ios::end);
  ifstream::pos_type size = is.tellg();
  char * memblock = new char [size];
    
  is.seekg (0, ios::beg);
  is.read (memblock, size);
  is.close();

  Ptr<Blob> readBlob = Ptr<Blob>(new Blob(memblock, size));

  Ptr<Data> readData = Data::decodeFromWire (readBlob);

  security::Certificate cert(*readData); 

  // DERendec endec;
  
  // endec.printDecoded(cert.content(), "", 0);
}

BOOST_AUTO_TEST_CASE(PolicyManagerLoad)
{
  Ptr<security::OSXPrivatekeyStorage> privateStoragePtr = Ptr<security::OSXPrivatekeyStorage>::Create();
  cerr << "GET privateStore" << endl;
  security::BasicPolicyManager policyManager("/Users/yuyingdi/Test/policy", privateStoragePtr);
  cerr << "GET policyManager" << endl;
  try{
  policyManager.displayPolicy();
  cerr << policyManager.getTrustAnchor(Name("/ndn/KSK-1376698603/ID-CERT/0"))->getName().toUri() << endl;
  }catch(security::SecException & e){
    cerr << e.Msg() << endl;
  }
}

BOOST_AUTO_TEST_CASE(AES_CIPHER)
{
  security::AesCipher encrypt(string("test"));
  string plainData = "abcdefg";
  Blob blob(plainData.c_str(), plainData.size());
  Ptr<Blob> encryptedPtr = encrypt.encrypt(blob);

  string xmlStr = encrypt.toXmlStr();
  Ptr<security::AesCipher> decryptPtr = security::AesCipher::fromXmlStr(xmlStr);

  cout << decryptPtr->getKeyName() << endl;
  Ptr<Blob> decryptedPtr = decryptPtr->decrypt(*encryptedPtr);
  string result(decryptedPtr->buf(), decryptedPtr->size());
  cout << result << endl;
}

BOOST_AUTO_TEST_CASE(BasicEncryptionManagerTest)
{
  Ptr<security::OSXPrivatekeyStorage> privateStoragePtr = Ptr<security::OSXPrivatekeyStorage>::Create();
  security::BasicEncryptionManager encryptionManager(privateStoragePtr, "/Users/yuyingdi/Test/encryption.db");

  cerr << "create encryptionManager" << endl;

  // encryptionManager.createSymKey(Name("/ndn/ucla.edu/yingdi/test/symkey"), security::KEY_TYPE_AES);
  string plainData = "abcdefg";
  Blob blob(plainData.c_str(), plainData.size());

  Ptr<Blob> encryptedBlobPtr = encryptionManager.encrypt(Name("/ndn/ucla.edu/yingdi/test/symkey"), blob, true, security::EM_CFB_AES);
  Ptr<Blob> decryptedBlobPtr = encryptionManager.decrypt(Name("/ndn/ucla.edu/yingdi/test/symkey"), *encryptedBlobPtr, true, security::EM_CFB_AES);

  string result(decryptedBlobPtr->buf(), decryptedBlobPtr->size());
  cout << result << endl;
}

BOOST_AUTO_TEST_CASE(KeyChainTest)
{
  using namespace ndn::security;

  Ptr<OSXPrivatekeyStorage> privateStorage = Ptr<OSXPrivatekeyStorage>::Create();
  Ptr<IdentityManager> identityManager = Ptr<IdentityManager>(new IdentityManager(Ptr<BasicIdentityStorage>::Create(), privateStorage));
  Ptr<PolicyManager> policyManager = Ptr<PolicyManager>(new BasicPolicyManager("/Users/yuyingdi/Test/policy", privateStorage));
  Ptr<EncryptionManager> encryptionManager = Ptr<EncryptionManager>(new BasicEncryptionManager(privateStorage, "/Users/yuyingdi/Test/encryption.db"));
  Ptr<CertificateCache> certificateCache = Ptr<CertificateCache>(new BasicCertificateCache());
  Keychain keychain(identityManager, policyManager, encryptionManager, certificateCache);
  
  Data data;
  data.setName(Name("/ndn/ucla.edu/yingdi/testdata"));
  string contentStr = "hello, world!";
  Content content(contentStr.c_str(), contentStr.size());
  data.setContent(content);

  
  try{
  keychain.signByIdentity(data, Name("/ndn/ucla.edu/yingdi"));
  
  // cout << boolalpha << keychain.verifyData(data) << endl;
  }catch(SecException & e){
    cerr << e.Msg() << endl;
  }
}

BOOST_AUTO_TEST_CASE(DUMP)
{
  security::DumpCertificate dump;
  dump.dump();
}

BOOST_AUTO_TEST_SUITE_END()
