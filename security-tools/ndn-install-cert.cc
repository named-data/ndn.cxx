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
#include <cryptopp/base64.h>

#include "ndn.cxx/security/identity/osx-privatekey-storage.h"
#include "ndn.cxx/security/identity/basic-identity-storage.h"
#include "ndn.cxx/security/identity/identity-manager.h"
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
getCertBlob(const string& fileName)
{
  ifstream ifs (fileName.c_str());
  string str((istreambuf_iterator<char>(ifs)),
              istreambuf_iterator<char>());
  
  string firstLine = "-----BEGIN NDN ID CERT-----\n";
  string lastLine = "-----END NDN ID CERT-----";

  int fPos = str.find(firstLine) + firstLine.size();
  int lPos = str.rfind(lastLine);

  string certBits = str.substr(fPos, lPos-fPos);
  
  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(certBits.c_str()), certBits.size(), true,
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
  string certFileName;
  bool setAsKeyDefault = false;
  bool setAsIdDefault = false;
  bool any = false;

  po::options_description desc("General options");
  desc.add_options()
    ("help,h", "produce help message")
    ("cert_file,f", po::value<string>(&certFileName), "file name of the ceritificate")
    ("key_default,K", "set the certificate as the default certificate of the key")
    ("id_default,I", "set the certificate as the default certificate of the identity")
    ("any,A", "add any certificate, NOT recommended!")
    ;
  
  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cout << desc << "\n";
      return 1;
    }

  if (0 == vm.count("cert_file"))
    {
      cout << "cert_file must be specified" << endl;
      cout << desc << endl;
      return 1;
    }
  
  if (vm.count("key_default"))
    {
      setAsKeyDefault = true;
    }

  if (vm.count("id_default"))
    {
      setAsIdDefault = true;
    }

  if (vm.count("any"))
    {
      any = true;
    }
  
  Ptr<Blob> certBlob = getCertBlob (certFileName);
  
  Ptr<ndn::Data> certData= Data::decodeFromWire (certBlob);
  Ptr<security::IdentityCertificate> cert = Ptr<security::IdentityCertificate>(new security::IdentityCertificate(*certData));

  cout << "get cert" << endl;
  
  Ptr<security::BasicIdentityStorage> publicStorage = Ptr<security::BasicIdentityStorage>::Create();
    cout<<"1"<<endl;
  Ptr<security::OSXPrivatekeyStorage> privateStorage = Ptr<security::OSXPrivatekeyStorage>::Create();
    cout<<"2"<<endl;
  security::IdentityManager identityManager(publicStorage, privateStorage);
    cout<<"3"<<endl;
  if(setAsIdDefault)
    {
      identityManager.addCertificateAsIdentityDefault(cert);
      return 0;
    }
  else if(setAsKeyDefault)
    {
      identityManager.addCertificateAsDefault(cert);
      return 0;
    }
  else if(any)
    {
      cerr << "here!" << endl;
      publicStorage->addAnyCertificate(cert);
      return 0;
    }
  else
    { 
      publicStorage->addCertificate(cert);
      return 0;
    }
}
