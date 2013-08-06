/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *                     Zhenkai Zhu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "ndn.cxx/interest.h"
#include "ndn.cxx/error.h"

#include <boost/test/unit_test.hpp>
#include <fstream>

using namespace ndn;
using namespace std;
using namespace boost;

BOOST_AUTO_TEST_SUITE(WireTests)

BOOST_AUTO_TEST_CASE (InterestTest)
{
  Interest i;
  i.setName (Name ("/hello/world"));

  ofstream of ("interest.ccnb");
  i.encodeToWire (of);
  
  BOOST_CHECK_EQUAL (1, 1);
}

BOOST_AUTO_TEST_SUITE_END()
