/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *                     Zhenkai Zhu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include <boost/test/unit_test.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/regex/regex.h"

#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/security/certificate/der.h"
#include "ndn.cxx/security/certificate/publickey.h"
#include "ndn.cxx/security/certificate/certificate-subdescrpt.h"
#include "ndn.cxx/security/policy/identity-policy.h"
#include "ndn.cxx/security/policy/basic-policy-manager.h"
#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/identity/basic-identity-storage.h"
#include "ndn.cxx/security/identity/osx-privatekey-store.h"

#include "ndn.cxx/fields/signature-sha256-with-rsa.h"


#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;
using namespace ndn;


BOOST_AUTO_TEST_SUITE(SecurityTests)

Ptr<Data> generateCertificate(Name keyName, Ptr<security::Publickey> pubKey)
{
  Ptr<Data> data = Create<Data>();
  
  Name certName;
  certName.append(keyName).append("ID-CERT").append("0");
  data->setName(certName);

  vector< Ptr<security::CertificateSubDescrypt> > subject;
  subject.push_back(Ptr<security::CertificateSubDescrypt>(new security::CertificateSubDescrypt("2.5.4.41", keyName.toUri())));
  tm current = boost::posix_time::to_tm(time::Now());
  current.tm_hour = 0;
  current.tm_min  = 0;
  current.tm_sec  = 0;
  Time notBefore = boost::posix_time::ptime_from_tm(current);
  current.tm_year = current.tm_year + 20;
  Time notAfter = boost::posix_time::ptime_from_tm(current);
  security::CertificateData certData(notBefore, notAfter, subject, pubKey);

  Ptr<Blob> certBlob = certData.toDER();

  Content content(certBlob->buf(), certBlob->size());
  data->setContent(content);
  
  return data;
}

BOOST_AUTO_TEST_CASE (Basic)
{
  string keyName = "/ndn/ucla/yingdi";
  security::OSXPrivatekeyStore keystore;
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
  string keyName = "/ndn/ucla/yingdi";
  security::DERendec endec;

  security::OSXPrivatekeyStore keystore;
  try{
    Data data;
    // //.../DNS/.../zsk-seq#(for key)/NDNCERT/certSeq#(for certificate)
    // Name name = Name("/ndn/ucla/DNS/yingdi/zsk-1/NDNCERT/20130722");

    // data.setName(name);
    
    // Ptr<Blob> keyPtr = readKey("out1.pub");
    // Content content;
    // content.setContent(*keyPtr);
    // content.setTimeStamp();
    // content.setType(Content::KEY);
    
    // data.setContent(content);
    
    // Signature sig;
    // KeyLocator keyLocator;
    // keyLocator.setType(KeyLocator::KEYNAME);
    // keyLocator.setKeyName(name);

    // data.setSignature(sig);
    

    // endec.PrintBlob(keystore.PublicKeyDigest(keyName, security::KEY_TYPE_RSA, security::KEY_PUBLIC_OPENSSL, security::DIGEST_SHA256), "");
  }catch (security::SecException & e){
    cerr << e.Msg() << endl;
  }

}

BOOST_AUTO_TEST_CASE (IdentityPolicy)
{
  security::IdentityPolicy policy("^(<>*)<DNS>(<>*)$", "^(<>*)<DNS>(<>*)<><NDNCERT>", ">=", "\\1\\2", "\\1\\2", true);
  ostringstream oss;
  oss << *policy.toXmlElement();

  cout << oss.str() << endl;

  security::IdentityPolicy::fromXmlElement(policy.toXmlElement());

  
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

BOOST_AUTO_TEST_CASE (IdentityStorage)
{
  try{
    security::BasicIdentityStorage idStore;

    cout << boolalpha << idStore.doesIdentityExist(Name("/ndn/ucla.edu/yingdi")) << endl;

    Name keyName = idStore.getNewKeyName(Name("/ndn/ucla.edu/yingdi"), true);

    string blobBits = "1234567890";
    Ptr<Blob> blobPtr = Ptr<Blob>(new Blob(blobBits.c_str(), blobBits.size()));
    
    // idStore.addKey(keyName, security::KEY_TYPE_DSA, blobPtr);

    idStore.activateKey(Name("/ndn/ucla.edu/yingdi/KSK-1375992917"));

    idStore.deactivateKey(Name("/ndn/ucla.edu/yingdi/KSK-1375992917"));

    // idStore.getAnyCertificate(Name("/ndn/edu/ucla/KSK-123456789/ID-CERT"));


  }catch(security::SecException & e){
    cerr << e.Msg();
  }
}

BOOST_AUTO_TEST_CASE (IdentityManager)
{
  Ptr<security::BasicIdentityStorage> publicStorage = Ptr<security::BasicIdentityStorage>::Create();
  Ptr<security::OSXPrivatekeyStore> privateStorage = Ptr<security::OSXPrivatekeyStore>::Create();

  security::IdentityManager identityManager(publicStorage, privateStorage);

  Ptr<security::Publickey> signingRequest = NULL;
  identityManager.createIdentity(Name("/ndn"));


  Name ndn_DSK_Name = identityManager.generateRSAKeyPair(Name("/ndn"));
  signingRequest = identityManager.getPublickey(ndn_DSK_Name);
  Ptr<Data> ndn_DSK_unsign_cert = generateCertificate(ndn_DSK_Name, signingRequest);

  identityManager.signByIdentity(*ndn_DSK_unsign_cert, Name("/ndn"));
  security::Certificate ndn_DSK_cert(*ndn_DSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_DSK_cert);



  identityManager.createIdentity(Name("/ndn/ucla.edu"));
  Name ndn_UCLA_KSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu"), true);


  signingRequest = identityManager.getPublickey(ndn_UCLA_KSK_name);
  Ptr<Data> ndn_UCLA_KSK_unsign_cert = generateCertificate(ndn_UCLA_KSK_name, signingRequest);


  identityManager.signByIdentity(*ndn_UCLA_KSK_unsign_cert, Name("/ndn"));
  security::Certificate ndn_UCLA_KSK_cert(*ndn_UCLA_KSK_unsign_cert);


  identityManager.addCertificateAsDefault(ndn_UCLA_KSK_cert);

  Name ndn_UCLA_DSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu"));
  signingRequest = identityManager.getPublickey(ndn_UCLA_DSK_name);
  Ptr<Data> ndn_UCLA_DSK_unsign_cert = generateCertificate(ndn_UCLA_DSK_name, signingRequest);
  
  identityManager.signByIdentity(*ndn_UCLA_DSK_unsign_cert, Name("/ndn/ucla.edu"));
  security::Certificate ndn_UCLA_DSK_cert(*ndn_UCLA_DSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_UCLA_DSK_cert);



  identityManager.createIdentity(Name("/ndn/ucla.edu/yingdi"));
  Name ndn_Yingdi_KSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu/yingdi"), true);


  signingRequest = identityManager.getPublickey(ndn_Yingdi_KSK_name);
  Ptr<Data> ndn_Yingdi_KSK_unsign_cert = generateCertificate(ndn_Yingdi_KSK_name, signingRequest);


  identityManager.signByIdentity(*ndn_Yingdi_KSK_unsign_cert, Name("/ndn/ucla.edu"));
  security::Certificate ndn_Yingdi_KSK_cert(*ndn_Yingdi_KSK_unsign_cert);

  identityManager.addCertificateAsDefault(ndn_Yingdi_KSK_cert);


  Name ndn_Yingdi_DSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu/yingdi"));
  signingRequest = identityManager.getPublickey(ndn_Yingdi_DSK_name);
  Ptr<Data> ndn_Yingdi_DSK_unsign_cert = generateCertificate(ndn_Yingdi_DSK_name, signingRequest);
  
  identityManager.signByIdentity(*ndn_Yingdi_DSK_unsign_cert, Name("/ndn/ucla.edu/yingdi"));
  security::Certificate ndn_Yingdi_DSK_cert(*ndn_Yingdi_DSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_Yingdi_DSK_cert);

  

  identityManager.createIdentity(Name("/ndn/ucla.edu/yingdi/app"));
  Name ndn_APP_KSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu/yingdi/app"), true);


  signingRequest = identityManager.getPublickey(ndn_APP_KSK_name);
  Ptr<Data> ndn_APP_KSK_unsign_cert = generateCertificate(ndn_APP_KSK_name, signingRequest);


  identityManager.signByIdentity(*ndn_APP_KSK_unsign_cert, Name("/ndn/ucla.edu/yingdi"));
  security::Certificate ndn_APP_KSK_cert(*ndn_APP_KSK_unsign_cert);

  identityManager.addCertificateAsDefault(ndn_APP_KSK_cert);


  Name ndn_APP_DSK_name = identityManager.generateRSAKeyPair(Name("/ndn/ucla.edu/yingdi/app"));
  signingRequest = identityManager.getPublickey(ndn_APP_DSK_name);
  Ptr<Data> ndn_APP_DSK_unsign_cert = generateCertificate(ndn_APP_DSK_name, signingRequest);
  
  identityManager.signByIdentity(*ndn_APP_DSK_unsign_cert, Name("/ndn/ucla.edu/yingdi/app"));
  security::Certificate ndn_APP_DSK_cert(*ndn_APP_DSK_unsign_cert);

  identityManager.addCertificateAsIdentityDefault(ndn_APP_DSK_cert);
}

BOOST_AUTO_TEST_CASE(PrivateStore)
{
  security::OSXPrivatekeyStore privateStorage;
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

BOOST_AUTO_TEST_CASE(PolicyManager)
{
  Ptr<security::OSXPrivatekeyStore> privateStoragePtr = Ptr<security::OSXPrivatekeyStore>::Create();
  security::BasicIdentityStorage identityStorage;

  security::BasicPolicyManager policyManager("/Users/yuyingdi/Test/policy", privateStoragePtr, "/ndn/ucla.edu/yingdi/app/0", true);
  
  Ptr<security::IdentityPolicy> vPolicy = Ptr<security::IdentityPolicy>(new security::IdentityPolicy("^(<>*)<DNS>(<>*)$", "^(<>*)<DNS>(<>*)<><NDNCERT>", ">=", "\\1\\2", "\\1\\2", true));
  policyManager.setVerificationPolicy(vPolicy);

  Ptr<Data> dataPtr = identityStorage.getCertificate(Name("/ndn/DSK-1376411829/ID-CERT/0"), true);
  security::Certificate cert(*dataPtr);
  
  policyManager.setTrustAnchor(cert);

  cerr << "SavePolicy" << endl;
  
  policyManager.savePolicy();
  
}

BOOST_AUTO_TEST_CASE(PolicyManagerLoad)
{
  Ptr<security::OSXPrivatekeyStore> privateStoragePtr = Ptr<security::OSXPrivatekeyStore>::Create();

  security::BasicPolicyManager policyManager("/Users/yuyingdi/Test/policy", privateStoragePtr, "/ndn/ucla.edu/yingdi/app/0", true);
  
  cerr << policyManager.getTrustAnchor(Name("/ndn/DSK-1376411829/ID-CERT/0"))->get << endl;
}

BOOST_AUTO_TEST_SUITE_END()
