/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/regex/regex-backref-manager.h"
#include "ndn.cxx/regex/regex-component.h"
#include "ndn.cxx/regex/regex-componentset-matcher.h"
#include "ndn.cxx/regex/regex-patternlist-matcher.h"
#include "ndn.cxx/regex/regex-repeat-matcher.h"
#include "ndn.cxx/regex/regex-backref-matcher.h"
#include "ndn.cxx/regex/regex-top-matcher.h"

#include <boost/test/unit_test.hpp>

#include <iostream>

using namespace ndn;
using namespace std;

BOOST_AUTO_TEST_SUITE(RegexTests)

BOOST_AUTO_TEST_CASE (Basic)
{
  regex::RegexBRManager * backRefManager = new regex::RegexBRManager();
  Name name("/ndn/ucla.edu/ab/ndn-cert/");

//   try{
//     Name name("/ndn/ucla.edu/a{b}/ndn-cert/");
//   }
//   catch(boost::exception &e){
//     std::cerr << boost::diagnostic_information (e) << std::endl;
//   }


  try{
  /* Check boost::regex */
//    string sStr("a{b}");
//    boost::regex r("a\\{b\\}");
//    cout << "Basic Result: " << boolalpha << boost::regex_match(sStr, r) << endl;


  /* Check RegexComponent */
  //  regex::RegexComponent component("a{b}", backRefManager, false);
  //  cout << boolalpha << component.Match(name, 2) << endl;
  
  /* Check RegexComponentSetMatcher */
//   regex::RegexComponentSetMatcher componentSetMatcher("[!<ndn-key><ndn-cert>]", backRefManager);
//   cout << "Result: " << boolalpha << componentSetMatcher.Match(name, 3) << endl;

  /* Check RegexRepeatMatcher */
//   regex::RegexRepeatMatcher repeatMatcher("<ndn>{2,3}", backRefManager, 5);
//   cout << "Result: " << boolalpha << repeatMatcher.Match(name, 0, 1) << endl;
  
  /* Check RegexPatternListMatcher */
//   regex::RegexPatternListMatcher patternListMatcher("<ndn><ucla\\.edu>", backRefManager);
//   cout << "Result: " << boolalpha << patternListMatcher.Match(name, 0, 2) << endl;

  /* CheckBackRefMatcher */
//   regex::RegexBackRefMatcher backRefMatcher("(<ndn>(<ucla\\.edu>))", backRefManager);
//   cout << "Result: " << boolalpha << backRefMatcher.Match(name, 0, 2) << endl;
//   cout << "RefNum: " << backRefManager->GetNum() << endl;
//   cout << "matcher1: " << backRefManager->GetBackRef(0)->GetExpr() << endl;
//   cout << "matcher2: " << backRefManager->GetBackRef(1)->GetExpr() << endl;
  /* CheckTopMatcher */
  regex::RegexTopMatcher topMatcher("(<ndn>(<ucla\\.edu>))");
  cout << "Result: " << boolalpha << topMatcher.cMatch(name, 0, 3) << " Name: " << topMatcher.getMatchResult() << endl;

  }
  catch (regex::RegexException &e){
    cout << e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_SUITE_END()
