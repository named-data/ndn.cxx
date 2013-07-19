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
  Ptr<Blob> pSig = keystore.Sign(keyName, security::KEY_TYPE_RSA, security::DIGEST_SHA1, pTestData);

  ofstream os("sig.sig");
  os.write(pSig->buf(), pSig->size());
  cerr << pSig->size()<< endl;

  
  cout << boolalpha << keystore.Verify(keyName, security::KEY_TYPE_RSA, security::DIGEST_SHA1, pTestData, pSig) << endl;

  try{
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
  
  keystore.ExportPublicKey(keyName, security::KEY_TYPE_RSA, security::KEY_X509, "");
}

BOOST_AUTO_TEST_SUITE_END()
