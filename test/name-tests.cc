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

#include "ndn.cxx/fields/name.h"
#include "ndn.cxx/fields/name-component.h"
#include "ndn.cxx/error.h"

#define BOOST_TEST_MAIN 1

#include <boost/test/unit_test.hpp>

using namespace ndn;
using namespace std;
using namespace boost;

BOOST_AUTO_TEST_SUITE(NameTests)

BOOST_AUTO_TEST_CASE (Component)
{
  name::Component x;
  BOOST_CHECK_EQUAL (x.size (), 0);

  x = name::Component ("test");
  BOOST_CHECK_EQUAL (x.size (), 4);

  x = name::Component ("%21test");
  BOOST_CHECK_EQUAL (x.size (), 5);

  BOOST_CHECK_EQUAL (x.toUri (), "!test");

  x = name::Component ("%20test");
  BOOST_CHECK_EQUAL (x.size (), 5);

  BOOST_CHECK_EQUAL (x.toUri (), "%20test");
}

BOOST_AUTO_TEST_CASE (Basic)
{
  Name empty = Name ();
  Name root = Name ("/");
  BOOST_CHECK_EQUAL (empty, root);
  BOOST_CHECK_EQUAL (empty, Name ("/"));
  BOOST_CHECK_EQUAL (root.size(), 0);

  empty.append ("hello");
  empty.append ("world");
  BOOST_CHECK_EQUAL (empty.size(), 2);
  BOOST_CHECK_EQUAL (empty.toUri(), "/hello/world");
  empty = empty + root;
  BOOST_CHECK_EQUAL (empty.toUri(), "/hello/world");
  BOOST_CHECK_EQUAL (empty.get (0).toUri (), "hello");
  BOOST_CHECK_EQUAL (empty.getSubName(1, 1), Name("/world"));
  Name name("/hello/world");
  BOOST_CHECK_EQUAL (empty, name);
  BOOST_CHECK_EQUAL (name, Name("/hello") + Name("/world"));

  name.appendSeqNum (1);
  name.appendSeqNum (255);
  name.appendSeqNum (256);
  name.appendSeqNum (1234567890);

  BOOST_CHECK_EQUAL (name.toUri (), "/hello/world/%00%01/%00%FF/%00%01%00/%00I%96%02%D2");

  BOOST_CHECK_EQUAL (name.get (5).toSeqNum (), 1234567890);
  BOOST_CHECK_EQUAL (name.get (4).toSeqNum (), 256);
  BOOST_CHECK_EQUAL (name.get (3).toSeqNum (), 255);
  BOOST_CHECK_EQUAL (name.get (2).toSeqNum (), 1);

  BOOST_CHECK_EQUAL (name.get (-1).toUri (), "%00I%96%02%D2");

  BOOST_CHECK_EQUAL (Name ("/%00").get (0).toSeqNum (), 0);

  const char tmp [] = {0, 1, 2, 3, 0x50};
  BOOST_CHECK_EQUAL (Name ().append (tmp, sizeof(tmp)).toUri (), "/%00%01%02%03P");

  BOOST_CHECK_EQUAL (Name ().append ("entr\u00E9e", sizeof ("entr\u00E9e")-1).toUri (), "/entr%C3%A9e");

  Name appendName ("/hello/you");
  appendName.append (Name ("/hello/you/too"));
  BOOST_CHECK_EQUAL (appendName.toUri (), "/hello/you/hello/you/too");

  Name appendSelf ("/hello/you");
  appendSelf.append (appendSelf);
  BOOST_CHECK_EQUAL (appendSelf.toUri (), "/hello/you/hello/you");

  Name withVersion ("/hello.txt/%FD%95-%25U1%DE%04/%00%01");
  BOOST_REQUIRE_NO_THROW (withVersion.get (1).toVersion ());
  BOOST_CHECK_EQUAL (withVersion.get (1).toVersion (), 41989409896259076);

  BOOST_CHECK_EQUAL (Name ("/%00%01%00").get (0).toSeqNum (), 256);
}

BOOST_AUTO_TEST_CASE (Advanced)
{
  BOOST_REQUIRE_THROW (Name (""),       error::Name);
  BOOST_REQUIRE_THROW (Name ("//"), error::Name);
  BOOST_REQUIRE_THROW (Name ("ndn://"), error::Name);
  BOOST_REQUIRE_THROW (Name ("bla"),    error::Name);
  BOOST_REQUIRE_THROW (Name ("bla/"),   error::Name);
  BOOST_REQUIRE_THROW (Name ("http:/test"), error::Name);

  BOOST_CHECK_EQUAL (Name ("ndn:///").toUri (), "/");
  BOOST_CHECK_EQUAL (Name ("/").toUri (), "/");
  BOOST_CHECK_EQUAL (Name ("///").toUri (), "/");
  BOOST_CHECK_EQUAL (Name ("////////////////////////////////////////////////").toUri (), "/");
  BOOST_CHECK_EQUAL (Name ("ndn://bla:random@something-else:0000/actual/name").toUri (), "/actual/name");
  BOOST_CHECK_EQUAL (Name ("/slash/").toUri (), "/slash");
}

BOOST_AUTO_TEST_CASE (Ordering)
{
  // check "canonical" ordering
  BOOST_CHECK_EQUAL (Name ("/test"), Name ("/test"));
  BOOST_CHECK_GE (Name ("/test"), Name ("/aaaa"));
  BOOST_CHECK_GT (Name ("/test"), Name ("/aaaa"));
  BOOST_CHECK_GT (Name ("/test/test/test"), Name ("/test/test"));
  BOOST_CHECK_GE (Name ("/test/test/test"), Name ("/test/test"));
  BOOST_CHECK_GE (Name ("/test/test/test"), Name ("/test/test/test"));

  BOOST_CHECK_LE (Name ("/test"), Name ("/aaaaa"));
  BOOST_CHECK_LT (Name ("/test"), Name ("/aaaaa"));
  BOOST_CHECK_LT (Name ("/test/test"), Name ("/test/test/test"));
  BOOST_CHECK_LE (Name ("/test/test"), Name ("/test/test/test"));
  BOOST_CHECK_LE (Name ("/test/test/test"), Name ("/test/test/test"));
}

BOOST_AUTO_TEST_SUITE_END()
