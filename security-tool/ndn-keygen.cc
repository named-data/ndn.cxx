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
#include <string>

#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/option.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
namespace po = boost::program_options;

#include "ndn.cxx/security/identity/osx-privatekey-store.h"
#include "ndn.cxx/fields/name.h"

using namespace std;
using namespace ndn;

string getOutputFile(const Name &name){
  Name::const_iterator it = name.begin();
  string filename = "";
  
  for(; it != name.end(); it++){
    filename += ("-" + it->toUri());
  }
  
  filename.erase(0, 1);

  return filename;
}

security::KeyType getKeyType(string keyType){
  if("RSA" == keyType){
    return security::KEY_TYPE_RSA;
  }
  else{
    cerr << "Unrecoganized key type option" << endl;
    exit(3);
  }
}

int main(int argc, char** argv)	
{
  // po::options_description opts( "General options" );
  // po::variables_map config;
  // string output;

  // try{
  //   opts.add_options()
  //     ("help,h", "Print this help message" )
  //     ("name,n", po::value<string>(), "Name of the key, e.g., /ndn/ucla.edu/alice/")
  //     ("type,t", po::value<string>()->default_value("RSA"), "Type of the key, e.g., RSA")
  //     ("size,s", po::value<int>()->default_value(2048), "Length of the key bits, e.g., 2048")
  //     ("format,f", po::value<string>()->default_value("PEM"), "Format of the output file, e.g. PEM, NDN")
  //     ("output,o", po::value<string>(), "Name of outputfile");
    
  //   po::store(po::parse_command_line(argc, argv, opts), config);
  // }catch(po::error e){
  //   cerr << opts << endl;
  //   exit(-1);
  // }
  
  // if(config.count("help")){
  //   cerr << opts << endl;
  //   exit(0);
  // }
  
  // if(!config.count("name")){
  //   cerr << "Please specify the key name by using -n option" << endl;
  //   cerr << opts << endl;
  //   exit(1);
  // }
  
  // Name name(config["name"].as<string>());

  // if(!config.count("output"))
  //   output = getOutputFile(name);
  // else
  //   output = config["output"].as<string>();

  // string format = config["format"].as<string>();
  
  // security::OSXPrivatekeyStore keystore;

  // string keyName = config["name"].as<string>();
  // string keyType = config["type"].as<string>();
  // int keySize = config["size"].as<int>();

  // if(1024 > keySize && "RSA" == keyType){
  //   cerr << "RSA key size must be larger thatn 1024" << endl;
  //   exit(4);
  // }

  // try{
  //   keystore.generateKeyPair(keyName, 
  //                            getKeyType(keyType),
  //                            keySize);
  // }catch(security::SecException e){
  //   cerr << e.Msg() << endl;
  //   exit(-2);
  // }

  // if("PEM" == format){
  //   output += ".pem";
  //   keystore.ExportPublicKey(keyName, getKeyType(keyType), security::KEY_PUBLIC_OPENSSL, output, true);
  // }
  // if("DER" == format){
  //   output += ".der";
  //   keystore.ExportPublicKey(keyName, getKeyType(keyType), security::KEY_PUBLIC_OPENSSL, output, false);
  // }
  // else if("NDN" == format){
  //   output += ".pubcert";
  // }
  // else{
  //   cerr << "Unrecoganized output format option" << endl;
  //   exit(2);
  // }

  

  // cerr << output << endl;

  return 0;
}
