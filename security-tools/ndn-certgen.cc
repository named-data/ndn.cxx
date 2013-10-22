/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <iostream>
#include <fstream>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/regex.hpp>
#include <cryptopp/base64.h>

#include "ndn.cxx/security/identity/osx-privatekey-storage.h"
#include "ndn.cxx/security/identity/basic-identity-storage.h"
#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/helpers/der/der.h"
#include "ndn.cxx/helpers/der/visitor/print-visitor.h"
#include "ndn.cxx/helpers/der/visitor/publickey-visitor.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

string 
getOutputFileName(const string& certName)
{     
  string result = certName;
  if('/' == *result.begin())
    result.erase(result.begin());
  if('/' == *(result.end()-1))
    result.erase(result.end()-1);


  int pos = result.find('/', 1);
  while(string::npos != pos)
    {
      result[pos] = '-';
      pos = result.find('/', pos + 1);
    }

  return result + ".cert";
}

Ptr<Blob> 
getKeyBlob(const string& fileName)
{
  ifstream ifs (fileName.c_str());
  string str((istreambuf_iterator<char>(ifs)),
              istreambuf_iterator<char>());
  
  string firstLine = "-----BEGIN RSA PUBLIC KEY-----\n";
  string lastLine = "-----END RSA PUBLIC KEY-----\n";

  int fPos = str.find(firstLine) + firstLine.size();
  int lPos = str.rfind(lastLine);

  string keyBits = str.substr(fPos, lPos-fPos);
  
  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(keyBits.c_str()), keyBits.size(), true,
			    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  return Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
}

void
printBlob(const Blob & blob, string indent, int offset)
{
  cout << indent;

  int count = 0;
  for(int i = offset; i < blob.size(); i++)
    {
      cout << " " << hex << setw(2) << setfill('0') << (int)(uint8_t)blob[i];
      count++;
      if(8 == count)
	{
	  count = 0;
	  cout << "\n" << indent;
	}
    }
  cout << endl;
}

int main(int argc, char** argv)	
{
  string keyName;
  string notBeforeStr;
  string notAfterStr;
  string sName;
  string reqFile;
  char certType;
  string signId;

  po::options_description desc("General options");
  desc.add_options()
    ("help,h", "produce help message")
    ("key_name,n", po::value<string>(&keyName), "key name, for example, /ndn/ucla.edu/alice/DSK-123456789")
    ("not_before,S", po::value<string>(&notBeforeStr), "certificate starting date, YYYYMMDDhhmmss")
    ("not_after,E", po::value<string>(&notAfterStr), "certificate ending date, YYYYMMDDhhmmss")
    ("subject_name,N", po::value<string>(&sName), "subject name")
    ("request,r", po::value<string>(&reqFile), "request file name")
    ("cert_type,t", po::value<char>(&certType)->default_value('i'), "certificate type, 'i' for identity certificate")
    ("sign_id,s", po::value<string>(&signId), "signing Identity")
    ;
  
  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cout << desc << "\n";
      return 1;
    }
  
  if (0 == vm.count("sign_id"))
    {
      cout << "sign_id must be specified!" << "\n";
      return 1;
    }

  if (0 == vm.count("key_name"))
    {
      cout << "key_name must be specified" << endl;
      return 1;
    }
  
  Name certName = Name(keyName);

  switch (certType)
    {
    case 'i':
      certName.append("ID-CERT");
      break;
    default:
      cerr << "Unrecongized cert type" << "\n";
      cerr << desc << endl;
      return 1;
    }

  TimeInterval ti = time::NowUnixTimestamp();
  ostringstream oss;
  oss << ti.total_seconds();
  certName.append(oss.str());
  cout<<"s1"<<endl;
    cout<<certName.toUri()<<endl;
  Time notBefore;
  Time notAfter;
  try{
    if (0 == vm.count("not_before"))
      {
        notBefore = boost::posix_time::second_clock::universal_time();
      }
    else
      {
        notBefore = boost::posix_time::from_iso_string(notBeforeStr.substr(0, 8) + "T" + notBeforeStr.substr(8, 6));
      }

  
    if (0 == vm.count("not_after"))
      {
        notAfter = notBefore + boost::posix_time::hours(24*365);
      }
    else
      {
        notAfter = boost::posix_time::from_iso_string(notAfterStr.substr(0, 8) + "T" + notAfterStr.substr(8, 6));
        if(notAfter < notBefore)
          {
            cout << "not_before is later than not_after" << endl;
            return 1;
          }
      }
  }catch(exception & e){
    cerr << "Error in converting validity timestamp!" << endl;
    return 1;
  }
  cout<<"s2"<<endl;

    
  if (0 == vm.count("request"))
    {
      cout << "request file must be specified" << endl;
      return 1;
    }

  Ptr<Blob> keyBlob = getKeyBlob(reqFile);

  boost::iostreams::stream<boost::iostreams::array_source> is (keyBlob->buf (), keyBlob->size ());
  Ptr<der::DerNode> node = der::DerNode::parse(reinterpret_cast<InputIterator &>(is));
  der::PublickeyVisitor pubkeyVisitor;
  Ptr<security::Publickey> publickey = boost::any_cast<Ptr<security::Publickey> >(node->accept(pubkeyVisitor));
  cout<<"s3"<<endl;

  if (0 == vm.count("subject_name"))
    {
      cout << "subject_name must be specified" << endl;
      return 1;
    }

  security::CertificateSubDescrypt subDescryptName("2.5.4.41", sName);
  Ptr<security::IdentityCertificate> certificate = Create<security::IdentityCertificate>();
//    cout<<"here"<<endl;
  certificate->setName(certName);
  certificate->setNotBefore(notBefore);
  certificate->setNotAfter(notAfter);
  certificate->setPublicKeyInfo(*publickey);
  certificate->addSubjectDescription(subDescryptName);
    certificate->encode();
  Ptr<security::BasicIdentityStorage> publicStorage = Ptr<security::BasicIdentityStorage>::Create();
  Ptr<security::OSXPrivatekeyStorage> privateStorage = Ptr<security::OSXPrivatekeyStorage>::Create();
  security::IdentityManager identityManager(publicStorage, privateStorage);

  Name signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name(signId));

  identityManager.signByCertificate(*certificate, signingCertificateName);

  Ptr<Blob> dataBlob = certificate->encodeToWire();

  string outputFileName = getOutputFileName(certName.toUri());
  ofstream ofs(outputFileName.c_str());
    Content c = certificate->getContent();
    cout<<"type: "<<c.getType()<<endl;

  ofs << "-----BEGIN NDN ID CERT-----\n";
  string encoded;
  CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(dataBlob->buf()), 
  			    dataBlob->size(), 
  			    true,
  			    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
  ofs << encoded;
  ofs << "-----END NDN ID CERT-----\n";
  ofs.close();
  return 0;

}
