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

#include <boost/test/unit_test.hpp>

#include <iostream>

using namespace ndn;
using namespace std;

BOOST_AUTO_TEST_SUITE(RegexTests)

BOOST_AUTO_TEST_CASE (Basic)
{
  regex::RegexBRManager * backRefManager = NULL;
  try{
    //    Name name("/ndn/ucla.edu/a{b}/ndn-cert/");
    Name name("/ndn/ucla.edu/ab/ndn-cert/");
  }
  catch(boost::exception &e){
    std::cerr << boost::diagnostic_information (e) << std::endl;
  }

  /* Check boost::regex */
//   string sStr("ndnkeys");
//   boost::regex r(".*keys");
//   cout << boolalpha << boost::regex_match(sStr, r) << endl;


  /* Check RegexComponent */
  //  regex::RegexComponent component("a{b}", backRefManager, false);
  //  cout << boolalpha << component.Match(name, 2) << endl;
  
}

BOOST_AUTO_TEST_SUITE_END()
