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

#include "ndn.cxx/wrapper/fake-wrapper.h"
#include "ndn.cxx/wrapper/closure.h"
#include "ndn.cxx/security/keychain.h"
#include "ndn.cxx/security/identity/osx-privatekey-store.h"
#include <boost/bind.hpp>
#include <unistd.h>

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
verifiedError(Ptr<Interest> interest)
{
  cout << "unverified" << endl;
}

static void
unverified(Ptr<Data> data)
{
  cout << "timeout" << endl;
}

BOOST_AUTO_TEST_CASE(Fake)
{

  Ptr<security::OSXPrivatekeyStore> privateStoragePtr = Ptr<security::OSXPrivatekeyStore>::Create();
  Ptr<security::Keychain> keychain = Ptr<security::Keychain>(new security::Keychain(privateStoragePtr, "/Users/yuyingdi/Test/policy", "/Users/yuyingdi/Test/encryption.db"));
  
  try{
    FakeWrapper wrapper(keychain);
    Ptr<Interest> interestPtr = Ptr<Interest>(new Interest(Name("/ndn/ucla.edu/yingdi/app/DSK-1376698615/ID-CERT/0")));
    Ptr<Closure> closure = Ptr<Closure> (new Closure(boost::bind(verifiedPrint, _1),
						     boost::bind(timeout, _1, _2),
						     boost::bind(verifiedError, _1),
						     Closure::UnverifiedDataCallback()
						     )
					 );
    wrapper.sendInterest(interestPtr, closure);
    sleep(3);
  }catch(security::SecException & e){
    cerr << e.Msg() << endl;
  }
  

}
  
BOOST_AUTO_TEST_SUITE_END()
