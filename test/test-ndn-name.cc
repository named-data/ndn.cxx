/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013 University of California, Los Angeles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "ndn.cxx/name.h"

#define BOOST_TEST_MAIN 1

#include <boost/test/unit_test.hpp>

using namespace ndn;
using namespace std;
using namespace boost;

BOOST_AUTO_TEST_SUITE(ndnNameTests)

BOOST_AUTO_TEST_CASE (ndnNameTest)
{
  Name empty = Name();
  Name root = Name("/");
  BOOST_CHECK_EQUAL(empty, root);
  BOOST_CHECK_EQUAL(empty, Name ("/"));
  BOOST_CHECK_EQUAL(root.size(), 0);
  empty.append("hello");
  empty.append("world");
  BOOST_CHECK_EQUAL(empty.size(), 2);
  BOOST_CHECK_EQUAL(empty.toUri(), "/hello/world");
  empty = empty + root;
  BOOST_CHECK_EQUAL(empty.toUri(), "/hello/world");
  BOOST_CHECK_EQUAL(Name::asString (empty.get (0)), "hello");
  BOOST_CHECK_EQUAL(empty.getSubName(1, 1), Name("/world"));
  Name name("/hello/world");
  BOOST_CHECK_EQUAL(empty, name);
  BOOST_CHECK_EQUAL(name, Name("/hello") + Name("/world"));


  name.appendSeqNum (1);
  name.appendSeqNum (255);
  name.appendSeqNum (256);
  name.appendSeqNum (1234567890);

  BOOST_CHECK_EQUAL (name.toUri (), "/hello/world/%00%01/%00%ff/%00%00%01/%00%d2%02%96I");

  BOOST_CHECK_EQUAL (Name::asSeqNum (name.get (5)), 1234567890);
  BOOST_CHECK_EQUAL (Name::asSeqNum (name.get (4)), 256);
  BOOST_CHECK_EQUAL (Name::asSeqNum (name.get (3)), 255);
  BOOST_CHECK_EQUAL (Name::asSeqNum (name.get (2)), 1);

  BOOST_CHECK_EQUAL (Name::asUriString (name.get (-1)), "%00%d2%02%96I");
  // Charbuf related stuff will be checked in other place
}

BOOST_AUTO_TEST_SUITE_END()
