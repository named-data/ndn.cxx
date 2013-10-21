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

int main(int argc, char** argv)	
{
  string certFileName;
  bool setDefaultId = false;
  bool setDefaultKey = false;
  bool setDefaultCert = false;
  string name;

  po::options_description desc("General options");
  desc.add_options()
    ("help,h", "produce help message")
    ("default_id,I", "set default identity")
    ("default_key,K", "set default key of the identity")
    ("default_cert,C", "set default certificate of the key")
    ("name,n", po::value<string>(&name), "the name to set")
    ;

  // po::positional_options_description p;
  // p.add("name", -1);
  
  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  // po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cout << desc << "\n";
      return 1;
    }

  int optCount = vm.count("default_id") + vm.count("default_key") + vm.count("default_cert");

  if (1 != optCount)
    {
      cout << "one and only one of default_id/key/cert must be specified" << endl;
      cout << desc << endl;
      return 1;
    }

  Ptr<security::BasicIdentityStorage> publicStorage = Ptr<security::BasicIdentityStorage>::Create();

  if (vm.count("default_id"))
    {
      Name idName(name);
      publicStorage->setDefaultIdentity(idName);
      return 0;
    }

  if (vm.count("default_key"))
    {
      Name keyName(name);
      publicStorage->setDefaultKeyNameForIdentity(keyName);
      return 0;
    }
  
  if (vm.count("default_cert"))
    {
      Name certName(name);
      Ptr<security::IdentityCertificate> identityCertificate = Ptr<security::IdentityCertificate>(new security::IdentityCertificate(*publicStorage->getCertificate(certName, false)));
      Name keyName = identityCertificate->getPublicKeyName();
      publicStorage->setDefaultCertificateNameForKey (keyName, certName);
      return 0;
    }
}
