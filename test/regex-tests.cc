/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/common.h"

#include "ndn.cxx/regex/regex-backref-manager.h"
#include "ndn.cxx/regex/regex-component.h"
#include "ndn.cxx/regex/regex-componentset-matcher.h"
#include "ndn.cxx/regex/regex-patternlist-matcher.h"
#include "ndn.cxx/regex/regex-repeat-matcher.h"
#include "ndn.cxx/regex/regex-backref-matcher.h"
#include "ndn.cxx/regex/regex-top-matcher.h"

#include <boost/test/unit_test.hpp>
#include <boost/regex.hpp>

#include <iostream>

using namespace ndn;
using namespace ndn::regex;
using namespace std;

BOOST_AUTO_TEST_SUITE(RegexTests)

BOOST_AUTO_TEST_CASE (ComponentMatcher)
{
  try{
    Ptr<RegexBRManager> backRef = Ptr<RegexBRManager>::Create();
    Ptr<RegexComponent> cm = Ptr<RegexComponent>(new RegexComponent ("a", backRef));
    bool res = cm->match(Name("/a/b/"), 0, 1);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri(), string("a"));

    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexComponent>(new RegexComponent ("a", backRef));
    res = cm->match(Name("/a/b/"), 1, 1);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexComponent>(new RegexComponent ("(c+)\\.(cd)", backRef));
    res = cm->match(Name("/ccc.cd/b/"), 0, 1);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri(), string("ccc.cd"));
    BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[0].toUri(), string("ccc"));
    BOOST_CHECK_EQUAL(backRef->getBackRef (1)->getMatchResult ()[0].toUri(), string("cd"));
  }catch(RegexException & e){
    cerr<< e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_CASE (ComponentSetMatcher)
{
  try{
    Ptr<RegexBRManager> backRef = Ptr<RegexBRManager>::Create();
    Ptr<RegexComponentSetMatcher> cm = Ptr<RegexComponentSetMatcher>(new RegexComponentSetMatcher ("<a>", backRef));
    bool res = cm->match(Name("/a/b/"), 0, 1);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri(), string("a"));
    
    res = cm->match(Name("/a/b/"), 1, 1);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);
    
    res = cm->match(Name("/a/b/"), 0, 2);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexComponentSetMatcher>(new RegexComponentSetMatcher ("[<a><b><c>]", backRef));
    res = cm->match(Name("/a/b/d"), 1, 1);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri(), string("b"));

    res = cm->match(Name("/a/b/d"), 2, 1);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);
 
    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexComponentSetMatcher>(new RegexComponentSetMatcher ("[^<a><b><c>]", backRef));
    res = cm->match(Name("/b/d"), 1, 1);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);    
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri(), string("d"));

  }catch(RegexException &e){
    cerr<< e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_CASE (RepeatMatcher)
{
  try{
    Ptr<RegexBRManager> backRef = Ptr<RegexBRManager>::Create();
    Ptr<RegexRepeatMatcher> cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("[<a><b>]*", backRef, 8));
    bool res = cm->match(Name("/a/b/c"), 0, 0);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    cm->match(Name("/a/b/c"), 0, 2);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));



    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("[<a><b>]+", backRef, 8));
    res = cm->match(Name("/a/b/c"), 0, 0);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    res = cm->match(Name("/a/b/c"), 0, 2);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));



    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("<.*>*", backRef, 4));
    res = cm->match(Name("/a/b/c/d/e/f/"), 0, 6);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 6);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("c"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toUri (), string("d"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[4].toUri (), string("e"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[5].toUri (), string("f"));



    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("<>*", backRef, 2));
    res = cm->match(Name("/a/b/c/d/e/f/"), 0, 6);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 6);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("c"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toUri (), string("d"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[4].toUri (), string("e"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[5].toUri (), string("f"));



    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("<a>?", backRef, 3));
    res = cm->match(Name("/a/b/c"), 0, 0);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("<a>?", backRef, 3));
    res = cm->match(Name("/a/b/c"), 0, 1);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));

    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("<a>?", backRef, 3));
    res = cm->match(Name("/a/b/c"), 0, 2);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);



    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("[<a><b>]{3}", backRef, 8));
    res = cm->match(Name("/a/b/a/d/"), 0, 2);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    res = cm->match(Name("/a/b/a/d/"), 0, 3);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 3);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("a"));

    res = cm->match(Name("/a/b/a/d/"), 0, 4);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);



    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("[<a><b>]{2,3}", backRef, 8));
    res = cm->match(Name("/a/b/a/d/e/"), 0, 2);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));

    res = cm->match(Name("/a/b/a/d/e/"), 0, 3);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 3);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("a"));

    res = cm->match(Name("/a/b/a/b/e/"), 0, 4);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    res = cm->match(Name("/a/b/a/d/e/"), 0, 1);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);


    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("[<a><b>]{2,}", backRef, 8));
    res = cm->match(Name("/a/b/a/d/e/"), 0, 2);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));

    res = cm->match(Name("/a/b/a/b/e/"), 0, 4);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toUri (), string("b"));

    res = cm->match(Name("/a/b/a/d/e/"), 0, 1);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);


    
    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("[<a><b>]{,2}", backRef, 8));
    res = cm->match(Name("/a/b/a/b/e/"), 0, 3);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    res = cm->match(Name("/a/b/a/b/e/"), 0, 2);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));

    res = cm->match(Name("/a/b/a/d/e/"), 0, 1);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));

    res = cm->match(Name("/a/b/a/d/e/"), 0, 0);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);


  }catch(RegexException &e){
    cerr<< e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_CASE (BackRefMatcher)
{
  try{
    Ptr<RegexBRManager> backRef = Ptr<RegexBRManager>::Create();
    Ptr<RegexBackRefMatcher> cm = Ptr<RegexBackRefMatcher>(new RegexBackRefMatcher ("(<a><b>)", backRef));
    backRef->pushRef(boost::static_pointer_cast<RegexMatcher>(cm));
    cm->lateCompile();
    bool res = cm->match(Name("/a/b/c"), 0, 2);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(backRef->getNum(), 1);

    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexBackRefMatcher>(new RegexBackRefMatcher ("(<a>(<b>))", backRef));
    backRef->pushRef(boost::static_pointer_cast<RegexMatcher>(cm));
    cm->lateCompile();
    res = cm->match(Name("/a/b/c"), 0, 2);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(backRef->getNum(), 2);
    BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[0].toUri(), string("a"));
    BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[1].toUri(), string("b"));
    BOOST_CHECK_EQUAL(backRef->getBackRef (1)->getMatchResult ()[0].toUri(), string("b"));



  }catch(RegexException &e){
    cerr<< e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_CASE (BackRefMatcherAdvanced)
{
  try{
    Ptr<RegexBRManager> backRef = Ptr<RegexBRManager>::Create();
    Ptr<RegexRepeatMatcher> cm = Ptr<RegexRepeatMatcher>(new RegexRepeatMatcher ("([<a><b>])+", backRef, 10));
    bool res = cm->match(Name("/a/b/c"), 0, 2);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(backRef->getNum(), 1);
    BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[0].toUri(), string("b"));
  }catch(RegexException &e){
    cerr<< e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_CASE (BackRefMatcherAdvanced2)
{
  try{
    Ptr<RegexBRManager> backRef = Ptr<RegexBRManager>::Create();
    Ptr<RegexPatternListMatcher> cm = Ptr<RegexPatternListMatcher>(new RegexPatternListMatcher ("(<a>(<b>))<c>", backRef));
    bool res = cm->match(Name("/a/b/c"), 0, 3);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 3);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("c"));
    BOOST_CHECK_EQUAL(backRef->getNum(), 2);
    BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[0].toUri(), string("a"));
    BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[1].toUri(), string("b"));
    BOOST_CHECK_EQUAL(backRef->getBackRef (1)->getMatchResult ()[0].toUri(), string("b"));

  }catch(RegexException &e){
    cerr<< e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_CASE (PatternListMatcher)
{
  try{
    Ptr<RegexBRManager> backRef = Ptr<RegexBRManager>::Create();
    Ptr<RegexPatternListMatcher> cm = Ptr<RegexPatternListMatcher>(new RegexPatternListMatcher ("<a>[<a><b>]", backRef));
    bool res = cm->match(Name("/a/b/c"), 0, 2);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));

    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexPatternListMatcher>(new RegexPatternListMatcher ("<>*<a>", backRef));
    res = cm->match(Name("/a/b/c"), 0, 1);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));

    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexPatternListMatcher>(new RegexPatternListMatcher ("<>*<a>", backRef));
    res = cm->match(Name("/a/b/c"), 0, 2);
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    backRef = Ptr<RegexBRManager>::Create();
    cm = Ptr<RegexPatternListMatcher>(new RegexPatternListMatcher ("<>*<a><>*", backRef));
    res = cm->match(Name("/a/b/c"), 0, 3);
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 3);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("c"));


  }catch(RegexException &e){
    cerr<< e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_CASE (TopMatcher)
{
  try{
    Ptr<RegexTopMatcher> cm = Ptr<RegexTopMatcher>(new RegexTopMatcher ("^<a><b><c>"));
    bool res = cm->match(Name("/a/b/c/d"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("c"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toUri (), string("d"));

    cm = Ptr<RegexTopMatcher>(new RegexTopMatcher ("<b><c><d>$"));
    res = cm->match(Name("/a/b/c/d"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("c"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toUri (), string("d"));

    cm = Ptr<RegexTopMatcher>(new RegexTopMatcher ("^<a><b><c><d>$"));
    res = cm->match(Name("/a/b/c/d"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("c"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toUri (), string("d"));

    res = cm->match(Name("/a/b/c/d/e"));
    BOOST_CHECK_EQUAL(res, false);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

    cm = Ptr<RegexTopMatcher>(new RegexTopMatcher ("<a><b><c><d>"));
    res = cm->match(Name("/a/b/c/d"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("c"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toUri (), string("d"));


    cm = Ptr<RegexTopMatcher>(new RegexTopMatcher ("<b><c>"));
    res = cm->match(Name("/a/b/c/d"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toUri (), string("a"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toUri (), string("b"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toUri (), string("c"));
    BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toUri (), string("d"));



  }catch(RegexException &e){
    cerr<< e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_CASE (TopMatcherAdvanced)
{
  try{
    Ptr<Regex> cm = Ptr<Regex>(new Regex ("^(<.*>*)<.*>"));
    bool res = cm->match(Name("/n/a/b/c"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->expand("\\1"), Name("/n/a/b/"));

    cm = Ptr<Regex>(new Regex ("^(<.*>*)<.*><c>(<.*>)<.*>"));
    res = cm->match(Name("/n/a/b/c/d/e/"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 6);
    BOOST_CHECK_EQUAL(cm->expand("\\1\\2"), Name("/n/a/d/"));

    cm = Ptr<Regex>(new Regex ("(<.*>*)<.*>$"));
    res = cm->match(Name("/n/a/b/c/"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->expand("\\1"), Name("/n/a/b/"));

    cm = Ptr<Regex>(new Regex ("<.*>(<.*>*)<.*>$"));
    res = cm->match(Name("/n/a/b/c/"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->expand("\\1"), Name("/a/b/"));

    cm = Ptr<Regex>(new Regex ("<a>(<>*)<>$"));
    res = cm->match(Name("/n/a/b/c/"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
    BOOST_CHECK_EQUAL(cm->expand("\\1"), Name("/b/"));

    cm = Ptr<Regex>(new Regex ("^<ndn><(.*)\\.(.*)><DNS>(<>*)<>"));
    res = cm->match(Name("/ndn/ucla.edu/DNS/yingdi/mac/ksk-1/"));
    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 6);
    BOOST_CHECK_EQUAL(cm->expand("<ndn>\\2\\1\\3"), Name("/ndn/edu/ucla/yingdi/mac/"));
    
  }catch(RegexException &e){
    cerr<< e.getMsg() << endl;
  }
}

BOOST_AUTO_TEST_CASE (SampleTest)
{
  try{
    int a = 0;
  }catch(RegexException &e){
    cerr<< e.getMsg() << endl;
  }
}


BOOST_AUTO_TEST_CASE (BoostRegex)
{
  boost::smatch subResult;

  bool res = boost::regex_match(string("abccd"), subResult, boost::regex("(abc)(cd)"));

  cout << boost::regex("").mark_count() << endl;

  cout << boolalpha << res << endl;
  //  cout << subResult[0]<< endl;   
  cout << subResult[1] << endl; 
  cout << subResult[2] << endl; 


}
BOOST_AUTO_TEST_SUITE_END()
