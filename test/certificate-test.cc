#include <boost/test/unit_test.hpp>

#include <iostream>
#include <fstream>
#include <tinyxml.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>

#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/security/certificate/certificate.h"
#include "ndn.cxx/security/certificate/der.h"

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
  Ptr<Blob> keyPtr = readKey("out1.pub");
  string notBefore = "20130718010203Z";
  string notAfter  = "20130719040506Z";
  vector<Ptr<security::CertificateSubDescrypt> > subjectList;
  subjectList.push_back(Ptr<security::CertificateSubDescrypt>(new security::CertificateSubDescrypt("2.5.4.10", "UCLA")));
  subjectList.push_back(Ptr<security::CertificateSubDescrypt>(new security::CertificateSubDescrypt("2.5.4.4", "Yu")));
  subjectList.push_back(Ptr<security::CertificateSubDescrypt>(new security::CertificateSubDescrypt("2.5.4.42", "Yingdi")));
  
  security::Certificate cert(notBefore, notAfter, subjectList, keyPtr);

  security::DERendec endec;

  endec.PrintDecoded(*cert.ToDER(), "", 0);

  security::Certificate cert2(*cert.ToDER());
  
  cert2.PrintCertificate();
}

BOOST_AUTO_TEST_SUITE_END()
