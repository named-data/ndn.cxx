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

#include "ndn.cxx/common.h"
#include "ndn.cxx/data.h"
#include "ndn.cxx/security/certificate/certificate.h"
#include "ndn.cxx/security/certificate/publickey.h"
#include "ndn.cxx/security/certificate/certificate-data.h"
#include "ndn.cxx/helpers/der/exception.h"
#include "ndn.cxx/helpers/der/der.h"
#include "ndn.cxx/helpers/der/visitor/print-visitor.h"
#include "ndn.cxx/helpers/der/visitor/certificate-data-visitor.h"

#include <sqlite3.h>
#include <fstream>

using namespace std;
using namespace ndn;

BOOST_AUTO_TEST_SUITE(DERTests)

static Ptr<security::Certificate>
getCert(const Name & name)
{
  sqlite3 * fakeDB;
  int res = sqlite3_open("/Users/yuyingdi/Test/fake-data.db", &fakeDB);
  
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2 (fakeDB, "SELECT data_blob FROM data WHERE data_name=?", -1, &stmt, 0);


  sqlite3_bind_text(stmt, 1, name.toUri().c_str(), name.toUri().size(), SQLITE_TRANSIENT);


  Ptr<security::Certificate> cert = NULL;
  if(sqlite3_step(stmt) == SQLITE_ROW)
    {
      Ptr<Data> data = Data::decodeFromWire(Ptr<Blob>(new Blob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0))));
      cert = Ptr<security::Certificate>(new security::Certificate(*data));
    }
  sqlite3_close (fakeDB);

  return cert;
}

BOOST_AUTO_TEST_CASE(DumpTestFile)
{
  Ptr<security::Certificate> cert = getCert(Name("/ndn/ucla.edu/yingdi/DSK-1376698612/ID-CERT/0"));
  
  ofstream kos("test-key.pub", ios::binary);
  Blob & keyBlob = cert->getPublicKeyInfo().getKeyBlob();
  kos.write(keyBlob.buf(), keyBlob.size());
  kos.close();
  
  ofstream cos("test-cert.data", ios::binary);
  cos.write(cert->content().buf(), cert->content().size());
  cos.close();
}

BOOST_AUTO_TEST_CASE(DisplayKey)
{
  ifstream kis ("test-key.pub", ios::binary);
  
  kis.seekg(0, ios::end);
  ifstream::pos_type size = kis.tellg();

  char * memblock = new char [size];
  
  kis.seekg(0, ios::beg);
  kis.read (memblock, size);
  kis.close();

  Blob blob(memblock, size);

  boost::iostreams::stream
    <boost::iostreams::array_source> is (memblock, size);

  try{
  Ptr<der::DerNode> node = der::DerNode::parse(reinterpret_cast<InputIterator &>(is));
  der::PrintVisitor printVisitor;
  node->accept(printVisitor, string(""));
  }catch(der::DerException & e){
    cout << e.Msg() << endl;
  }
}

BOOST_AUTO_TEST_CASE(DisplayCert)
{
  ifstream cis ("test-cert.data", ios::binary);
  
  cis.seekg(0, ios::end);
  ifstream::pos_type size = cis.tellg();

  char * memblock = new char [size];
  
  cis.seekg(0, ios::beg);
  cis.read (memblock, size);
  cis.close();

  Blob blob(memblock, size);

  boost::iostreams::stream
    <boost::iostreams::array_source> is (memblock, size);

  try{
  Ptr<der::DerNode> node = der::DerNode::parse(reinterpret_cast<InputIterator &>(is));
  der::PrintVisitor printVisitor;
  node->accept(printVisitor, string(""));
  }catch(der::DerException & e){
    cout << e.Msg() << endl;
  }
}

BOOST_AUTO_TEST_CASE(PrintVisitor)
{
  ifstream cis ("test-cert.data", ios::binary);
  
  cis.seekg(0, ios::end);
  ifstream::pos_type size = cis.tellg();

  char * memblock = new char [size];
  
  cis.seekg(0, ios::beg);
  cis.read (memblock, size);
  cis.close();

  Blob blob(memblock, size);

  boost::iostreams::stream
    <boost::iostreams::array_source> is (memblock, size);

  try{
  Ptr<der::DerNode> node = der::DerNode::parse(reinterpret_cast<InputIterator &>(is));
  der::PrintVisitor printVisitor;
  node->accept(printVisitor, string(""));
  }catch(der::DerException & e){
    cout << e.Msg() << endl;
  }
}

BOOST_AUTO_TEST_CASE(CertificateDataVisitor)
{
  ifstream cis ("test-cert.data", ios::binary);
  
  cis.seekg(0, ios::end);
  ifstream::pos_type size = cis.tellg();

  char * memblock = new char [size];
  
  cis.seekg(0, ios::beg);
  cis.read (memblock, size);
  cis.close();

  Blob blob(memblock, size);

  boost::iostreams::stream
    <boost::iostreams::array_source> is (memblock, size);

  try{
  Ptr<der::DerNode> node = der::DerNode::parse(reinterpret_cast<InputIterator &>(is));

  der::PrintVisitor printVisitor;
  node->accept(printVisitor, string(""));

  der::CertificateDataVisitor certDataVisitor;
  security::CertificateData certData;
  node->accept(certDataVisitor, boost::any(&certData));
  
  certData.printCertificate();

  }catch(der::DerException & e){
    cout << e.Msg() << endl;
  }
}


  
BOOST_AUTO_TEST_SUITE_END()

