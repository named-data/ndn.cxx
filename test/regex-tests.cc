/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/security/regex/regex-component.h"
#include "ndn.cxx/security/regex/regex-parser.h"

#include <boost/test/unit_test.hpp>

#include <iostream>

using namespace ndn;
using namespace std;

BOOST_AUTO_TEST_SUITE(RegexTests)

BOOST_AUTO_TEST_CASE (Basic)
{
  /* Check boost::regex */
//   string sStr("ndnkeys");
//   boost::regex r(".*keys");
//   cout << boolalpha << boost::regex_match(sStr, r) << endl;


  /* Check RegexComponent */

  /* Check Regex  

//   Check RegexParser
  regex::RegexParser::Compile("(^[abc]+[[xq]]{4,3})*[.*]$");
}

BOOST_AUTO_TEST_SUITE_END()
