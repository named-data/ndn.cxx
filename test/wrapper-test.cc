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
#include <boost/filesystem.hpp>
#include <unistd.h>
#include <fstream>

using namespace ndn;
namespace fs = boost::filesystem;

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

void 
publishIdentityCertificate(Ptr<Wrapper> wrapper)
{
  sqlite3 * fakeDB;
  fs::path identityDir = fs::path(getenv("HOME")) / ".ndn-identity";
  fs::create_directories (identityDir);
    
  int res = sqlite3_open((identityDir / "identity.db").c_str (), &fakeDB);
  
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2 (fakeDB, "SELECT certificate_data FROM certificate", -1, &stmt, 0);

  while(sqlite3_step(stmt) == SQLITE_ROW)
    {
      Blob dataBlob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0));    
      wrapper->putToNdnd(dataBlob);
    }

  sqlite3_close (fakeDB);
}

BOOST_AUTO_TEST_CASE(Real)
{

  using namespace ndn::security;

  Ptr<Keychain> keychain = Ptr<Keychain>::Create();

  ifstream is ("trust-anchor.dat", ios::binary);
  is.seekg (0, ios::end);
  ifstream::pos_type size = is.tellg();
  char * memblock = new char [size];    
  is.seekg (0, ios::beg);
  is.read (memblock, size);
  is.close();

  Ptr<Blob> readBlob = Ptr<Blob>(new Blob(memblock, size));
  Ptr<Data> readData = Data::decodeFromWire (readBlob);
  Ptr<IdentityCertificate> anchor = Ptr<IdentityCertificate>(new IdentityCertificate(*readData));   
  Ptr<SimplePolicyManager> policyManager = DynamicCast<SimplePolicyManager>(keychain->getPolicyManager());
  policyManager->addTrustAnchor(anchor);
  
  Ptr<Wrapper> wrapper = Ptr<Wrapper>(new Wrapper(keychain));

  publishIdentityCertificate(wrapper);

  Ptr<Interest> interestPtr = Ptr<Interest>(new Interest(Name("/ndn/ucla.edu/cathy/KEY/dsk-1382907978/ID-CERT/%FDRm%80K")));
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
