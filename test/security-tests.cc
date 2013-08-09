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


#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/security/certificate/der.h"
#include "ndn.cxx/security/policy/identity-policy.h"
#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/identity/basic-identity-storage.h"
#include "ndn.cxx/security/identity/osx-privatekey-store.h"

#include "ndn.cxx/fields/signature-sha256-with-rsa.h"


#include <iostream>
#include <fstream>

using namespace std;
using namespace ndn;


BOOST_AUTO_TEST_SUITE(SecurityTests)

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

  identityManager.createIdentity(Name("/ndn/ucla.edu/yingdi/"));
}

BOOST_AUTO_TEST_SUITE_END()
