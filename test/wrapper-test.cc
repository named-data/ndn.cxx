/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <boost/test/unit_test.hpp>

#include "ndn.cxx/wrapper/wrapper.h"
#include "ndn.cxx/wrapper/closure.h"
#include "ndn.cxx/security/keychain.h"
#include "ndn.cxx/security/identity/osx-privatekey-storage.h"
#include "ndn.cxx/security/policy/simple-policy-manager.h"
#include "ndn.cxx/security/policy/identity-policy-rule.h"
#include "ndn.cxx/security/identity/basic-identity-storage.h"
#include "ndn.cxx/security/encryption/basic-encryption-manager.h"
#include "ndn.cxx/security/cache/ttl-certificate-cache.h"
#include "ndn.cxx/regex/regex.h"
#include <sqlite3.h>
#include <boost/bind.hpp>
#include <unistd.h>
#include <fstream>

using namespace ndn;

BOOST_AUTO_TEST_SUITE(WrapperTests)

static void 
verifiedPrint(Ptr<Data> data)
{
  cout << "verified" << endl;
}

static void 
timeout(Ptr<Closure> closure, Ptr<Interest> interest)
{
  cout << "timeout" << endl;
}

static void
verifiedError(Ptr<Data> data)
{
  cout << "unverified" << endl;
}

static void
unverified(Ptr<Data> data)
{
  cout << "timeout" << endl;
}

static void
publishCert(Ptr<Interest> interestPtr, Ptr<Wrapper> wrapper)
{
  const Name & name = interestPtr->getName();
  Regex regex("^<>*<ID-CERT><>$");

  if(!regex.match(name))
    return;

  cout << "publishCert" << endl;

  sqlite3 * fakeDB;
  int res = sqlite3_open("/Users/yuyingdi/Test/fake-data.db", &fakeDB);
  
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2 (fakeDB, "SELECT data_blob FROM data WHERE data_name=?", -1, &stmt, 0);


  sqlite3_bind_text(stmt, 1, name.toUri().c_str(), name.toUri().size(), SQLITE_TRANSIENT);

  if(sqlite3_step(stmt) == SQLITE_ROW)
    {
      Blob dataBlob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));    
      wrapper->putToCcnd(dataBlob);
    }

  sqlite3_close (fakeDB);
}

void
publishAllCert(Ptr<Wrapper> wrapper)
{
  sqlite3 * fakeDB;
  int res = sqlite3_open("/Users/yuyingdi/Test/fake-data.db", &fakeDB);
  
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2 (fakeDB, "SELECT data_blob FROM data", -1, &stmt, 0);

  while(sqlite3_step(stmt) == SQLITE_ROW)
    {
      Blob dataBlob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));    
      wrapper->putToCcnd(dataBlob);
    }

  sqlite3_close (fakeDB);
}

BOOST_AUTO_TEST_CASE(Fake)
{

  // Ptr<security::OSXPrivatekeyStorage> privateStoragePtr = Ptr<security::OSXPrivatekeyStorage>::Create();
  // Ptr<security::Keychain> keychain = Ptr<security::Keychain>(new security::Keychain(privateStoragePtr, "/Users/yuyingdi/Test/policy", "/Users/yuyingdi/Test/encryption.db"));
  
  // try{
  //   FakeWrapper wrapper(keychain);
  //   Ptr<Interest> interestPtr = Ptr<Interest>(new Interest(Name("/ndn/ucla.edu/yingdi/app/DSK-1376698615/ID-CERT/0")));
  //   Ptr<Closure> closure = Ptr<Closure> (new Closure(boost::bind(verifiedPrint, _1),
  // 						     boost::bind(timeout, _1, _2),
  // 						     boost::bind(verifiedError, _1),
  // 						     Closure::UnverifiedDataCallback()
  // 						     )
  // 					 );
  //   wrapper.sendInterest(interestPtr, closure);
  //   sleep(3);
  // }catch(security::SecException & e){
  //   cerr << e.Msg() << endl;
  // }
  

}

BOOST_AUTO_TEST_CASE(Real)
{

  using namespace ndn::security;

  Ptr<OSXPrivatekeyStorage> privateStorage = Ptr<OSXPrivatekeyStorage>::Create();
  Ptr<IdentityManager> identityManager = Ptr<IdentityManager>(new IdentityManager(Ptr<BasicIdentityStorage>::Create(), privateStorage));
  Ptr<CertificateCache> certificateCache = Ptr<CertificateCache>(new TTLCertificateCache());
  Ptr<SimplePolicyManager> policyManager = Ptr<SimplePolicyManager>(new SimplePolicyManager(10, certificateCache));

  policyManager->addVerificationPolicyRule(Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^([^<KEY>]*)<KEY>(<>*)<KSK-.*><ID-CERT>",
											  "^([^<KEY>]*)<KEY><DSK-.*><ID-CERT>",
											  ">", "\\1\\2", "\\1", true)));
  policyManager->addVerificationPolicyRule(Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^([^<KEY>]*)<KEY><DSK-.*><ID-CERT>",
											  "^([^<KEY>]*)<KEY>(<>*)<KSK-.*><ID-CERT>",
											  "==", "\\1", "\\1\\2", true)));

  ifstream is ("trust-anchor.data", ios::binary);
  is.seekg (0, ios::end);
  ifstream::pos_type size = is.tellg();
  char * memblock = new char [size];    
  is.seekg (0, ios::beg);
  is.read (memblock, size);
  is.close();

  Ptr<Blob> readBlob = Ptr<Blob>(new Blob(memblock, size));
  Ptr<Data> readData = Data::decodeFromWire (readBlob);
  Ptr<IdentityCertificate> anchor = Ptr<IdentityCertificate>(new IdentityCertificate(*readData));   
  policyManager->addTrustAnchor(anchor);

  Ptr<EncryptionManager> encryptionManager = Ptr<EncryptionManager>(new BasicEncryptionManager(privateStorage, "/Users/yuyingdi/Test/encryption.db"));
  Ptr<Keychain> keychain = Ptr<Keychain>(new Keychain(identityManager, policyManager, encryptionManager));

  Ptr<Wrapper> wrapper = Ptr<Wrapper>(new Wrapper(keychain));

  // Name prefix("/ndn");
  // wrapper->setInterestFilter(prefix, boost::bind(publishCert, _1, wrapper));

  publishAllCert(wrapper);

  Ptr<Interest> interestPtr = Ptr<Interest>(new Interest(Name("/ndn/KEY/DSK-1376698604/ID-CERT/1382032856")));
  Ptr<Closure> closure = Ptr<Closure> (new Closure(boost::bind(verifiedPrint, _1),
						   boost::bind(timeout, _1, _2),
						   boost::bind(verifiedError, _1))
				       );


  wrapper->sendInterest(interestPtr, closure);
  sleep(5);
  wrapper->sendInterest(interestPtr, closure);
  while(true)
    {
      sleep(10);
    }
}
  
BOOST_AUTO_TEST_SUITE_END()
