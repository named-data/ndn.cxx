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
#include "ndn.cxx/data.h"
#include "ndn.cxx/error.h"

#include "ndn.cxx/fields/content.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/fields/key-locator.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

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

BOOST_AUTO_TEST_CASE (DataTest)
{
  Data data;
  data.setName(Name("/ndn/data/"));
  
  Ptr<signature::Sha256WithRsa> sha256sig = Create<signature::Sha256WithRsa>();

  string sigs = "signaturessignaturessignatures";
  sha256sig->setSignatureBits(Blob(sigs.c_str(), sigs.size()));
  
  string digest = "12345678901234567890123456789012";
  sha256sig->setPublisherKeyDigest(Blob(digest.c_str(), digest.size()));

  KeyLocator keyLocator;
  keyLocator.setType(KeyLocator::KEYNAME);
  keyLocator.setKeyName(Name("/ndn/data/key/"));
  sha256sig->setKeyLocator(keyLocator);

  data.setSignature(sha256sig);

  Content content;
  content.setTimeStamp();
  content.setType(Content::DATA);
  content.setFreshness();
  
  string contentStr = "contentcontentcontentcontentcontent";

  content.setContent(Blob(contentStr.c_str(), contentStr.size()));

  data.setContent(content);

  Ptr<Blob> unsignedData = data.encodeToUnsignedWire();
  Ptr<SignedBlob> signedBlobPtr = Ptr<SignedBlob>(new SignedBlob(unsignedData->buf(), unsignedData->size()));
  signedBlobPtr->setSignedPortion(0, unsignedData->size());
  data.setSignedBlob(signedBlobPtr);


  Ptr<Blob> encoded = data.encodeToWire ();

  Ptr<Data> decodedData = Data::decodeFromWire (encoded);

  BOOST_CHECK_EQUAL (decodedData->getName(), Name("/ndn/data/"));

  Ptr<signature::Sha256WithRsa> dSha256sig = DynamicCast<signature::Sha256WithRsa>(decodedData->getSignature());
  string decodedSig(dSha256sig->getSignatureBits().buf(), dSha256sig->getSignatureBits().size());

  BOOST_CHECK_EQUAL (decodedSig, sigs);

  BOOST_CHECK_EQUAL (dSha256sig->getKeyLocator().getKeyName(), Name("/ndn/data/key/"));
  
  string decodedDigestStr(dSha256sig->getPublisherKeyDigest().buf(), dSha256sig->getPublisherKeyDigest().size());
  BOOST_CHECK_EQUAL (decodedDigestStr, digest);

  string decodedContentStr(decodedData->content().buf(), decodedData->content().size());
  BOOST_CHECK_EQUAL (decodedContentStr, contentStr);
}

BOOST_AUTO_TEST_SUITE_END()
