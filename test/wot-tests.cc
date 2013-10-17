/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <boost/test/unit_test.hpp>

#include "ndn.cxx/security/certificate/intro-certificate-extension.h"
#include "ndn.cxx/helpers/der/visitor/print-visitor.h"

using namespace ndn;
using namespace std;
using namespace ndn::security;

BOOST_AUTO_TEST_SUITE(WebOfTrustTests)

BOOST_AUTO_TEST_CASE(IntroCertExtnTest)
{
  IntroCertificateExtension introExtn (Name("/ndn/ucla.edu/yingdi/"), IntroCertificateExtension::NORMAL_PRODUCER, 100);
  
  der::PrintVisitor printVisitor;
  introExtn.toDER()->accept(printVisitor, string(""));
}

BOOST_AUTO_TEST_SUITE_END()
