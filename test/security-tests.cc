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

#include "ndn.cxx/security/osx-privateKeyStore.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/security/certificate/der.h"

#include <boost/test/unit_test.hpp>

#include <iostream>
#include <fstream>

using namespace std;
using namespace ndn;


BOOST_AUTO_TEST_SUITE(SecurityTests)

BOOST_AUTO_TEST_CASE (Basic)
{
  string keyName = "/ndn/ucla/yingdi";
  security::OSXPrivateKeyStore keystore;
  //  keystore.GenerateKeyPair(keyName);
  
  string testData = "testDataTestData";
  Ptr<Blob> pTestData = Ptr<Blob>(new Blob(testData.c_str(), testData.size()));
  try{
    Ptr<Blob> pSig = keystore.Sign(keyName, security::KEY_TYPE_RSA, security::DIGEST_SHA256, pTestData);
    
    ofstream os("sig.sig");
    os.write(pSig->buf(), pSig->size());
    cerr << pSig->size()<< endl;
  
    cout << boolalpha << keystore.Verify(keyName, security::KEY_TYPE_RSA, security::DIGEST_SHA256, pTestData, pSig) << endl;

    Ptr<Blob> pEncrypt = keystore.Encrypt(keyName, pTestData);
    Ptr<Blob> pDecrypt = keystore.Decrypt(keyName, pEncrypt);

    string output(pDecrypt->buf(), pDecrypt->size());
    cout << output << endl;
  }catch (security::SecException & e){
    cerr << e.Msg() << endl;
  }

}

BOOST_AUTO_TEST_CASE (Export)
{
  string keyName = "/ndn/ucla/yingdi";
  security::OSXPrivateKeyStore keystore;
  
  keystore.ExportPublicKey(keyName, security::KEY_TYPE_RSA, security::KEY_PUBLIC_OPENSSL, "", false);
}

BOOST_AUTO_TEST_CASE (Digest)
{
  string keyName = "/ndn/ucla/yingdi";
  security::DERendec endec;

  security::OSXPrivateKeyStore keystore;
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

BOOST_AUTO_TEST_SUITE_END()
