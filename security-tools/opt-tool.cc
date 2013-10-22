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


void configuration(string _cert, string _inst_id, int _auto)
{
//    string query = 'http://cert.ndn.ucla.edu:5000/ndn/auth/v1.1/candidates/'+_inst_id;
//    std::string result = system( "./some_command" ) ;
}


int main(int argc, char** argv)
{
/*    string inst_id;
    string sign_id;
    string configure_file;
    
    po::options_description desc("General options");
    desc.add_options()
    ("help,h", "produce help message")
    ("institution name,i", po::value<string>(&inst_id), "institution id")
    ("signer id,s", po::value<string>(&sign_id), "signer id")
    ("configure file,f", po::value<string>(&configure_file), "configuration file");
    
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
    
    if (vm.count("help"))
    {
        cout << desc << "\n";
        return 1;
    }
*/
    if (string(argv[1]) == "self-sign")
    {
        Ptr<security::BasicIdentityStorage> publicStorage = Ptr<security::BasicIdentityStorage>::Create();
        Ptr<security::OSXPrivatekeyStorage> privateStorage = Ptr<security::OSXPrivatekeyStorage>::Create();
        security::IdentityManager identityManager(publicStorage, privateStorage);
        Ptr<security::IdentityCertificate> selfCert = identityManager.selfSign(Name(string(argv[2])));
//        selfCert.printCertificate();
        identityManager.addCertificateAsDefault(selfCert);
        cout<<identityManager.getDefaultIdentity().toUri()<<endl;
/*        Ptr<Blob> dataBlob = certificate->encodeToWire();
        string outputFileName = getOutputFileName(certName.toUri());
        ofstream ofs(outputFileName.c_str());
        
        ofs << "-----BEGIN NDN ID CERT-----\n";
        string encoded;
        CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(dataBlob->buf()),
                                  dataBlob->size(),
                                  true,
                                  new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
        ofs << encoded;
        ofs << "-----END NDN ID CERT-----\n";
        ofs.close();
*/
        
    }
    if (string(argv[1]) == "sign") //argv[2] the content to be signed argv[3] the signID
    {
    Ptr<security::BasicIdentityStorage> publicStorage = Ptr<security::BasicIdentityStorage>::Create();
    Ptr<security::OSXPrivatekeyStorage> privateStorage = Ptr<security::OSXPrivatekeyStorage>::Create();
    
    security::IdentityManager identityManager(publicStorage, privateStorage);
    Blob b(argv[2],strlen(argv[2]));
    Name signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name(argv[3]));

//        cout<<signingCertificateName.toUri()<<endl;
//    Name certName("/ndn/ucla.edu/xingyu/DSK-1379111405/ID-CERT/1379112388");
//    Name keyName = publicStorage->getKeyNameForCertificate(signingCertificateName);
    Ptr<security::IdentityCertificate> certificate = identityManager.getCertificate(signingCertificateName);
    Name keyName = certificate->getPublicKeyName();
        
    Ptr<Blob> sigBits = privateStorage->sign (b, keyName.toUri());

//    cout<<string(sigBits->buf(),sigBits->size())<<endl;
    string encoded;
    CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(sigBits->buf()),
                              sigBits->size(),
                              true,
                              new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
    char * cstr = new char [encoded.length()+1];
    std::strcpy (cstr, encoded.c_str());
//    cout<<cstr<<endl;
    char * ret = new char [encoded.length()+1];
    int now = 0;
    for (int i = 0; i < encoded.length()+1; i++)
    {
        if (cstr[i] != '\n')
        {
            ret[now] = cstr[i];
            now++;
        }
    }
//    cout<<now<<"  "<<encoded.length()+1<<endl;
    cout<<string(ret,now)<<endl;
    }
    
    if (string(argv[1]) == "nack") //argv[2] user key name argv[3] signer ID
    {
        Content nack_pkt("", 0, Content::NACK);
        Ptr<security::BasicIdentityStorage> publicStorage = Ptr<security::BasicIdentityStorage>::Create();
        Ptr<security::OSXPrivatekeyStorage> privateStorage = Ptr<security::OSXPrivatekeyStorage>::Create();
        
        security::IdentityManager identityManager(publicStorage, privateStorage);
        
        Data d;
        d.setContent(nack_pkt);
        string keyname = argv[2];
        keyname += "/refusal";
        d.setName(keyname);
        
        Name signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name(argv[3]));
        //    Name certName("/ndn/ucla.edu/xingyu/DSK-1379111405/ID-CERT/1379112388");

        identityManager.signByCertificate (d, signingCertificateName);
        Content c = d.getContent();
        cout<<c.getType()<<endl;
        
        Ptr<Blob> dataBlob = d.encodeToWire();
        string outputFileName = getOutputFileName(keyname);
        ofstream ofs(outputFileName.c_str());
        
        ofs << "-----BEGIN NDN ID CERT-----\n";
        string encoded;
        CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(dataBlob->buf()),
                                  dataBlob->size(),
                                  true,
                                  new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
        ofs << encoded;
        ofs << "-----END NDN ID CERT-----\n";
        ofs.close();
//        cout<<c.getType()<<endl;
        
    }
    //
    return 0;
    
}
