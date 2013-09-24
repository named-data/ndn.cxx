#include <boost/test/unit_test.hpp>

#include <iostream>
#include <fstream>
#include <tinyxml.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>

#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/security/certificate/certificate.h"
#include "ndn.cxx/security/certificate/publicKey.h"
#include "ndn.cxx/helpers/der/der.h"

using namespace std;
using namespace boost::posix_time;
using namespace CryptoPP;
using namespace ndn;

BOOST_AUTO_TEST_SUITE(CertificateTests)

Ptr<Blob> readKey(string filename)
{
  ifstream file (filename.c_str(), ios::in|ios::binary|ios::ate);

  if (file.is_open())
  {
    ifstream::pos_type size = file.tellg();
    char * memblock = new char [size];

    file.seekg (0, ios::beg);
    file.read (memblock, size);
    file.close();

    Ptr<Blob> cert = Ptr<Blob>::Create();
    
    cert->insert(cert->end(), memblock, memblock + size);

    delete[] memblock;

    return cert;
  }
  else cout << "Unable to open file";

  return 0;
}

BOOST_AUTO_TEST_CASE(Basic)
{
  // Ptr<Blob> keyPtr = readKey("out1.pub");
  // Time notBefore = from_iso_string("20130718T010203");
  // Time notAfter  = from_iso_string("20130719T040506");
  // vector<Ptr<security::CertificateSubDescrypt> > subjectList;
  // subjectList.push_back(Ptr<security::CertificateSubDescrypt>(new security::CertificateSubDescrypt("2.5.4.10", "UCLA")));
  // subjectList.push_back(Ptr<security::CertificateSubDescrypt>(new security::CertificateSubDescrypt("2.5.4.4", "Yu")));
  // subjectList.push_back(Ptr<security::CertificateSubDescrypt>(new security::CertificateSubDescrypt("2.5.4.42", "Yingdi")));
  
  // security::CertificateData cert(notBefore, notAfter, subjectList, Ptr<security::Publickey>(new security::Publickey(*keyPtr)));

  // security::DERendec endec;

  // endec.printDecoded(*cert.toDER(), "", 0);

  // security::CertificateData cert2(*cert.toDER());
  
  // cert2.printCertificate();
}

BOOST_AUTO_TEST_SUITE_END()
