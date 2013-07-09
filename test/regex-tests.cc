/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/security/regex/regex-backref-manager.h"
#include "ndn.cxx/security/regex/regex-component.h"
#include "ndn.cxx/security/regex/regex-componentset-matcher.h"

#include <boost/test/unit_test.hpp>

#include <iostream>

using namespace ndn;
using namespace std;

BOOST_AUTO_TEST_SUITE(RegexTests)

BOOST_AUTO_TEST_CASE (Basic)
{
  regex::RegexBRManager * backRefManager = NULL;
  Name name("/ndn/ucla.edu/ab/ndn-cert/");

//   try{
//     Name name("/ndn/ucla.edu/a{b}/ndn-cert/");
//   }
//   catch(boost::exception &e){
//     std::cerr << boost::diagnostic_information (e) << std::endl;
//   }



  /* Check boost::regex */
   string sStr("a{b}");
   boost::regex r("a\\{b\\}");
   cout << "Basic Result: " << boolalpha << boost::regex_match(sStr, r) << endl;


  /* Check RegexComponent */
  //  regex::RegexComponent component("a{b}", backRefManager, false);
  //  cout << boolalpha << component.Match(name, 2) << endl;
  
  /* Check RegexComponentSetMatcher */
  regex::RegexComponentSetMatcher componentSetMatcher("[!<ndn-key><ndn-cert>]", backRefManager);
  cout << "Compile: " << boolalpha << componentSetMatcher.Compile() << endl;
  cout << "Result: " << boolalpha << componentSetMatcher.Match(name, 3) << endl;
}

BOOST_AUTO_TEST_SUITE_END()
