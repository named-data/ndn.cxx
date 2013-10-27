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

#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/security/identity/identity-manager.h"

using namespace std;
using namespace ndn;
using namespace ndn::security;




BOOST_AUTO_TEST_SUITE(SecurityTests)

Name 
generateCertificate(IdentityManager& identityManager, 
                    const Name& identity, 
                    const Name& signCertName, 
                    bool ksk, 
                    const Time& notBefore, 
                    const Time& notAfter)
{
  Name keyName;
  Name keyPrefix;
  if(ksk)
    {
      keyName = identityManager.createIdentity(identity);
      keyPrefix = keyName.getPrefix(keyName.size()-2);
      keyPrefix.append("KEY").append(keyName.get(-2)).append(keyName.get(-1));
    }
  else
    {
      keyName = identityManager.generateRSAKeyPair(identity);
      keyPrefix = keyName.getPrefix(keyName.size()-1);
      keyPrefix.append("KEY").append(keyName.get(-1));
    }
  Ptr<IdentityCertificate> cert = identityManager.createIdentityCertificate (keyPrefix, 
                                                                             signCertName, 
                                                                             notBefore, 
                                                                             notAfter);
  identityManager.addCertificate(cert);
  identityManager.setDefaultKeyForIdentity(keyName, identity);
  identityManager.setDefaultCertificateForKey(*cert);  
  
  return cert->getName();
}

BOOST_AUTO_TEST_CASE(CertificateGeneration)
{
  try{
    IdentityManager identityManager;

    tm current = boost::posix_time::to_tm(time::Now());
    current.tm_hour = 0;
    current.tm_min  = 0;
    current.tm_sec  = 0;
    Time notBefore = boost::posix_time::ptime_from_tm(current);
    current.tm_year = current.tm_year + 20;
    Time notAfter = boost::posix_time::ptime_from_tm(current);

    Name ndn_ksk_name = identityManager.createIdentity(Name("/ndn"));
    Ptr<IdentityCertificate> ndn_ksk_selfsign_cert = identityManager.selfSign(ndn_ksk_name);
    identityManager.addCertificate(ndn_ksk_selfsign_cert);
    identityManager.setDefaultKeyForIdentity(ndn_ksk_name, Name("/ndn"));
    identityManager.setDefaultCertificateForKey(*ndn_ksk_selfsign_cert);

    Name ndn_dsk_cert_name = generateCertificate(identityManager, Name("/ndn"), ndn_ksk_selfsign_cert->getName(), false, notBefore, notAfter);    

    Name ucla_ksk_cert_name = generateCertificate(identityManager, Name("/ndn/ucla.edu"), ndn_dsk_cert_name, true, notBefore, notAfter);

    Name ucla_dsk_cert_name = generateCertificate(identityManager, Name("/ndn/ucla.edu"), ucla_ksk_cert_name, false, notBefore, notAfter);

    Name alice_ksk_cert_name = generateCertificate(identityManager, Name("/ndn/ucla.edu/alice"), ucla_dsk_cert_name, true, notBefore, notAfter);

    Name alice_dsk_cert_name = generateCertificate(identityManager, Name("/ndn/ucla.edu/alice"), alice_ksk_cert_name, false, notBefore, notAfter);

    Name bob_ksk_cert_name = generateCertificate(identityManager, Name("/ndn/ucla.edu/bob"), ucla_dsk_cert_name, true, notBefore, notAfter);

    Name bob_dsk_cert_name = generateCertificate(identityManager, Name("/ndn/ucla.edu/bob"), bob_ksk_cert_name, false, notBefore, notAfter);

    Name cathy_ksk_cert_name = generateCertificate(identityManager, Name("/ndn/ucla.edu/cathy"), ucla_dsk_cert_name, true, notBefore, notAfter);

    Name cathy_dsk_cert_name = generateCertificate(identityManager, Name("/ndn/ucla.edu/cathy"), cathy_ksk_cert_name, false, notBefore, notAfter);

  }catch(security::SecException& e){
    cerr << e.Msg() << endl;
  }
}

BOOST_AUTO_TEST_SUITE_END()
