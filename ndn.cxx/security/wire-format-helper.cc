/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "wire-format-helper.h"

#include "ndn.cxx/fields/content.h"
#include "ndn.cxx/fields/key-locator.h"
#include "ndn.cxx/wire/ccnb.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

#include <sstream>

using namespace std;
using namespace ndn::wire;

namespace ndn
{

namespace security
{
  static const char TYPES [][3] =  {
    {0x0C, 0x04, 0xC0},
    {0x10, 0xD0, 0x91},
    {0x18, 0xE3, 0x44},
    {0x28, 0x46, 0x3F},
    {0x2C, 0x83, 0x4A},
    {0x34, 0x00, 0x8A}
  };

  Ptr<Blob>
  Wire::toUnsignedWire(const Data & data)
  {
    ostringstream os;
    
    Ccnb::appendName (os, data.getName ()); // <Name>
    
    Ccnb::appendBlockHeader (os, Ccnb::CCN_DTAG_SignedInfo, Ccnb::CCN_DTAG); // <SignedInfo>

    Ptr<const signature::Sha256WithRsa> signature = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data.getSignature());

    Ccnb::appendTaggedBlob (os, Ccnb::CCN_DTAG_PublisherPublicKeyDigest, signature->getPublisherKeyDigest ());

    Ccnb::appendTimestampBlob (os, data.getContent ().getTimestamp ());

    Ccnb::appendTaggedBlob (os, Ccnb::CCN_DTAG_Type, TYPES [data.getContent ().getType ()], 3);

    if (data.getContent ().getFreshness () != Content::noFreshness)
      {
	Ccnb::appendTaggedNumber (os, Ccnb::CCN_DTAG_FreshnessSeconds,
				  data.getContent ().getFreshness ().total_seconds ());
      }

    if (data.getContent ().getFinalBlockId () != Content::noFinalBlock)
      {
	Ccnb::appendTaggedBlob (os, Ccnb::CCN_DTAG_FinalBlockID, data.getContent ().getFinalBlockId ());
      }
    
    Ccnb::appendBlockHeader (os, Ccnb::CCN_DTAG_KeyLocator, Ccnb::CCN_DTAG); // <KeyLocator>
    switch (signature->getKeyLocator ().getType ())
      {
      case KeyLocator::NOTSET:
          break;
      case KeyLocator::KEY:
	Ccnb::appendTaggedBlob (os, Ccnb::CCN_DTAG_Key, signature->getKeyLocator ().getKey ());
	break;
      case KeyLocator::CERTIFICATE:
	Ccnb::appendTaggedBlob (os, Ccnb::CCN_DTAG_Certificate, signature->getKeyLocator ().getCertificate ());
	break;
      case KeyLocator::KEYNAME:
	Ccnb::appendBlockHeader (os, Ccnb::CCN_DTAG_KeyName, Ccnb::CCN_DTAG); // <KeyName>
	Ccnb::appendName (os, signature->getKeyLocator ().getKeyName ());
	Ccnb::appendCloser (os); // </KeyName>
	break;
      }
    Ccnb::appendCloser (os); // </KeyLocator>
    
    Ccnb::appendCloser (os); // </SignedInfo>

    Ccnb::appendTaggedBlob (os, Ccnb::CCN_DTAG_Content, data.content ()); // <Content>

    string dataBytes = os.str();
    
    return Ptr<Blob>(new Blob(dataBytes.c_str(), dataBytes.size()));
  }

}//security

}//ndn
