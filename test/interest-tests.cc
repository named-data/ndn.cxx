/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012 University of California, Los Angeles
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

#include "ndn.cxx.h"
#include "ndn.cxx/ccnb.h"
#include <unistd.h>
#include <fstream>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/make_shared.hpp>

#include "logging.h"

using namespace ndn;
using namespace std;
using namespace boost;

BOOST_AUTO_TEST_SUITE(InterestTests)

static const string Interest1 ("\x01\xD2\xF2\x00\x05\x9A\x8E\x32\x00\x05\xA2\x8E\x32\x00\x05\xAA\x8E\x31\x00\x02"
                               "\xFA\x8E\x34\x00\x02\xD2\x8E\x30\x00\x03\x82\x95\xA0\x00\x00\x00",
                               36);

static const string Interest2 ("\x01\xD2\xF2\x00\x05\x9A\x8E\x32\x00\x05\xA2\x8E\x32\x00\x03\x82\x95\xA0\x00\x00"
                               "\x00",
                               21);

BOOST_AUTO_TEST_CASE (Basic)
{
  INIT_LOGGERS ();
  
  Interest i;
  i.setName (Name ("/test"));
  i.setMinSuffixComponents (2);
  i.setMaxSuffixComponents (2);
  i.setInterestLifetime (posix_time::seconds (10));
  i.setScope (Interest::SCOPE_LOCAL_CCND);
  i.setAnswerOriginKind (Interest::AOK_STALE);
  i.setChildSelector (Interest::CHILD_RIGHT);
  // i.setPublisherPublicKeyDigest (?);

  ostringstream os;
  int len = Ccnb::AppendInterest (os, i);
  BOOST_CHECK_EQUAL (len, Interest1.size ());
  string Interest0 = os.str ();
  BOOST_CHECK_EQUAL_COLLECTIONS (Interest0.begin (), Interest0.end (),
                                 Interest1.begin (), Interest1.end ());
}

BOOST_AUTO_TEST_CASE (Charbuf)
{
  INIT_LOGGERS ();

  Interest i;
  i.setName (Name ("/test"));
  i.setMinSuffixComponents (2);
  i.setMaxSuffixComponents (2);
  i.setInterestLifetime (posix_time::seconds (10));

  charbuf_stream stream;
  int len = Ccnb::AppendInterest (stream, i);
  
  BOOST_CHECK_EQUAL (len, Interest2.size ());

  BOOST_CHECK_EQUAL_COLLECTIONS (reinterpret_cast<char*> (stream.buf ().getBuf ()->buf),
                                 reinterpret_cast<char*> (stream.buf ().getBuf ()->buf+stream.buf ().getBuf ()->length),
                                 Interest2.begin (), Interest2.end ());
  
}

BOOST_AUTO_TEST_SUITE_END()
