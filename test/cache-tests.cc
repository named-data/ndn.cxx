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

#include "ndn.cxx/security/cache/ttl-certificate-cache.h"
#include "ndn.cxx/security/certificate/certificate.h"

#include <sqlite3.h>
#include <unistd.h>

using namespace ndn;
using namespace ndn::security;

BOOST_AUTO_TEST_SUITE(CacheTests)

Ptr<Certificate>
getCert(const Name & name)
{
  Ptr<Certificate> certificate = NULL;

  sqlite3 * fakeDB;
  int res = sqlite3_open("/Users/yuyingdi/Test/fake-data.db", &fakeDB);
  
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2 (fakeDB, "SELECT data_blob FROM data WHERE data_name=?", -1, &stmt, 0);

  sqlite3_bind_text(stmt, 1, name.toUri().c_str(), name.toUri().size(),  SQLITE_TRANSIENT);



  if(sqlite3_step(stmt) == SQLITE_ROW)
    {
      Ptr<const Blob> blob = Ptr<const Blob>(new Blob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0)));
      certificate = Ptr<Certificate>(new Certificate(*Data::decodeFromWire(blob)));
    }

  sqlite3_close (fakeDB);

  return certificate;
}

BOOST_AUTO_TEST_CASE(Basic)
{
  TimeInterval interval = time::Seconds(5);

  Ptr<Certificate> cert1 = getCert(Name("/ndn/DSK-1376698604/ID-CERT/0"));
  cert1->getContent().setFreshness(interval);
  Ptr<Certificate> cert2 = getCert(Name("/ndn/ucla.edu/DSK-1376698608/ID-CERT/0"));
  cert2->getContent().setFreshness(interval);
  Ptr<Certificate> cert3 = getCert(Name("/ndn/ucla.edu/yingdi/DSK-1376698612/ID-CERT/0"));
  cert3->getContent().setFreshness(interval);
  Ptr<Certificate> cert4 = getCert(Name("/ndn/ucla.edu/yingdi/app/DSK-1376698615/ID-CERT/0"));
  cert4->getContent().setFreshness(interval);
  Ptr<Certificate> cert5 = getCert(Name("/ndn/ucla.edu/yingdi/app/KSK-1376698614/ID-CERT/0"));
  cert5->getContent().setFreshness(interval);

  security::TTLCertificateCache cache(4, 2);

  cache.insertCertificate(cert1);
  sleep(1);
  cache.insertCertificate(cert2);
  sleep(1);
  cache.insertCertificate(cert3);
  sleep(1);
  cache.insertCertificate(cert4);
  sleep(1);
  cache.printContent();

  cout << endl;

  cache.insertCertificate(cert5);
  cache.printContent();

  Ptr<Certificate> tmpCertificate = cache.getCertificate(Name("/ndn/ucla.edu/DSK-1376698608/ID-CERT/0"));
  cache.printContent();

  sleep(3);
  
  cache.printContent();

}
BOOST_AUTO_TEST_SUITE_END()
