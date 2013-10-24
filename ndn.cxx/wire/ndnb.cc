/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "ndnb.h"
#include "ndn.cxx/error.h"

#include <boost/lexical_cast.hpp>

namespace ndn {
namespace wire {

#define NDN_TT_BITS 3
#define NDN_TT_MASK ((1 << NDN_TT_BITS) - 1)
#define NDN_MAX_TINY ((1 << (7-NDN_TT_BITS)) - 1)
#define NDN_TT_HBIT ((unsigned char)(1 << 7))

void
Ndnb::appendBlockHeader (std::ostream &os, size_t val, Ndnb::ndn_tt tt)
{
  unsigned char buf[1+8*((sizeof(val)+6)/7)];
  unsigned char *p = &(buf[sizeof(buf)-1]);
  size_t n = 1;
  p[0] = (NDN_TT_HBIT & ~Ndnb::NDN_CLOSE_TAG) |
  ((val & NDN_MAX_TINY) << NDN_TT_BITS) |
  (NDN_TT_MASK & tt);
  val >>= (7-NDN_TT_BITS);
  while (val != 0) {
    (--p)[0] = (((unsigned char)val) & ~NDN_TT_HBIT) | Ndnb::NDN_CLOSE_TAG;
    n++;
    val >>= 7;
  }
  os.write (reinterpret_cast<const char*> (p), n);
  // return n;
}

void
Ndnb::appendNumber (std::ostream &os, uint32_t number)
{
  std::string numberStr = boost::lexical_cast<std::string> (number);

  appendBlockHeader (os, numberStr.size (), Ndnb::NDN_UDATA);
  numberStr.size ();
  os.write (numberStr.c_str (), numberStr.size ());
}

void
Ndnb::appendName (std::ostream &os, const Name &name)
{
  Ndnb::appendBlockHeader (os, Ndnb::NDN_DTAG_Name, Ndnb::NDN_DTAG); // <Name>
  for (Name::const_iterator component = name.begin (); component != name.end (); component ++)
    {
      appendTaggedBlob (os, Ndnb::NDN_DTAG_Component, component->buf (), component->size ());
    }
  Ndnb::appendCloser (os);                                        // </Name>
}

void
Ndnb::appendTimestampBlob (std::ostream &os, const TimeInterval &time)
{
  // NDNx method function implements some markers, which are not really defined anywhere else...

  // Determine miminal number of bytes required to store the timestamp
  int required_bytes = 2; // 12 bits for fractions of a second, 4 bits left for seconds. Sometimes it is enough
  intmax_t ts = time.total_seconds () >> 4;
  for (;  required_bytes < 7 && ts != 0; ts >>= 8) // not more than 6 bytes?
     required_bytes++;

  appendBlockHeader(os, required_bytes, Ndnb::NDN_BLOB);

  // write part with seconds
  ts = time.total_seconds () >> 4;
  for (int i = 0; i < required_bytes - 2; i++)
    os.put ( ts >> (8 * (required_bytes - 3 - i)) );

  /* arithmetic contortions are to avoid overflowing 31 bits */
  ts = ((time.total_seconds () & 15) << 12) +
    (((time.total_nanoseconds () % 1000000000) / 5 * 8 + 195312) / 390625);
  for (int i = required_bytes - 2; i < required_bytes; i++)
    os.put ( ts >> (8 * (required_bytes - 1 - i)) );

  // return len + required_bytes;
}

void
Ndnb::appendExclude (std::ostream &os, const Exclude &exclude)
{
  appendBlockHeader (os, Ndnb::NDN_DTAG_Exclude, Ndnb::NDN_DTAG); // <Exclude>

  for (Exclude::const_reverse_iterator item = exclude.rbegin (); item != exclude.rend (); item ++)
    {
      if (!item->first.empty ())
        appendTaggedBlob (os, Ndnb::NDN_DTAG_Component, item->first.buf (), item->first.size ());
      if (item->second)
        {
          appendBlockHeader (os, Ndnb::NDN_DTAG_Any, Ndnb::NDN_DTAG); // <Any>
          appendCloser (os); // </Any>
        }
    }
  appendCloser (os); // </Exclude>
}

void
Ndnb::appendInterest (std::ostream &os, const Interest &interest)
{
  Ndnb::appendBlockHeader (os, Ndnb::NDN_DTAG_Interest, Ndnb::NDN_DTAG); // <Interest>

  // this is used for now as an interest template. Name should be empty
  // Ndnb::appendName (os, interest.getName ());
  Ndnb::appendName (os, Name ());                              // <Component>...</Component>...

  if (interest.getMinSuffixComponents () != Interest::ncomps)
    {
      appendTaggedNumber (os, Ndnb::NDN_DTAG_MinSuffixComponents, interest.getMinSuffixComponents ());
    }
  if (interest.getMaxSuffixComponents () != Interest::ncomps)
    {
      appendTaggedNumber (os, Ndnb::NDN_DTAG_MaxSuffixComponents, interest.getMaxSuffixComponents ());
    }
  if (interest.getExclude ().size () > 0)
    {
      appendExclude (os, interest.getExclude ());
    }
  if (interest.getChildSelector () != Interest::CHILD_DEFAULT)
    {
      appendTaggedNumber (os, Ndnb::NDN_DTAG_ChildSelector, interest.getChildSelector ());
    }
  if (interest.getAnswerOriginKind () != Interest::AOK_DEFAULT)
    {
      appendTaggedNumber (os, Ndnb::NDN_DTAG_AnswerOriginKind, interest.getAnswerOriginKind ());
    }
  if (interest.getScope () != Interest::NO_SCOPE)
    {
      appendTaggedNumber (os, Ndnb::NDN_DTAG_Scope, interest.getScope ());
    }
  if (!interest.getInterestLifetime ().is_negative ())
    {
      Ndnb::appendBlockHeader (os, Ndnb::NDN_DTAG_InterestLifetime, Ndnb::NDN_DTAG);
      Ndnb::appendTimestampBlob (os, interest.getInterestLifetime ());
      Ndnb::appendCloser (os);
    }
  // if (GetNonce()>0)
  //   {
  //     uint32_t nonce = interest.GetNonce();
  //     appendTaggedBlob (start, Ndnb::NDN_DTAG_Nonce, nonce);
  //   }

  // if (GetNack ()>0)
  //   {
  //     appendBlockHeader (start, Ndnb::NDN_DTAG_Nack, Ndnb::NDN_DTAG);
  //     appendNumber (start, interest.GetNack ());
  //     appendCloser (start);
  //   }
  Ndnb::appendCloser (os); // </Interest>
}

static void *SIGNATURE_Block = 0;
static void *SINATURE_INFO_PublisherPublicKeyDigest = reinterpret_cast<void *> (1);
static void *SINATURE_INFO_KeyLocator = reinterpret_cast<void *> (2);

static const char TYPES [][3] =  {
  {0x0C, 0x04, 0xC0},
  {0x10, 0xD0, 0x91},
  {0x18, 0xE3, 0x44},
  {0x28, 0x46, 0x3F},
  {0x2C, 0x83, 0x4A},
  {0x34, 0x00, 0x8A}
};

void
Ndnb::appendSignature (std::ostream &os, const signature::Sha256WithRsa &signature, void *userData)
{
  if (userData == SIGNATURE_Block)
    {
      Ndnb::appendBlockHeader (os, Ndnb::NDN_DTAG_Signature, Ndnb::NDN_DTAG); // <Signature>
      // if (signature.getDigestAlgorithm () != "2.16.840.1.101.3.4.2.1")
      //   {
      //     appendString (os, Ndnb::NDN_DTAG_DigestAlgorithm, signature.getDigestAlgorithm ());
      //   }
      appendTaggedBlob (os, Ndnb::NDN_DTAG_SignatureBits, signature.getSignatureBits ());
      Ndnb::appendCloser (os); // </Signature>
    }
  else if (userData == SINATURE_INFO_PublisherPublicKeyDigest)
    {
      Ndnb::appendTaggedBlob (os, Ndnb::NDN_DTAG_PublisherPublicKeyDigest, signature.getPublisherKeyDigest ());
    }
  else if (userData == SINATURE_INFO_KeyLocator)
    {
      Ndnb::appendBlockHeader (os, Ndnb::NDN_DTAG_Signature, Ndnb::NDN_DTAG); // <Signature>
      switch (signature.getKeyLocator ().getType ())
        {
        case KeyLocator::NOTSET:
          break;
        case KeyLocator::KEY:
          Ndnb::appendTaggedBlob (os, Ndnb::NDN_DTAG_Key, signature.getKeyLocator ().getKey ());
          break;
        case KeyLocator::CERTIFICATE:
          Ndnb::appendTaggedBlob (os, Ndnb::NDN_DTAG_Key, signature.getKeyLocator ().getCertificate ());
          break;
        case KeyLocator::KEYNAME:
          Ndnb::appendBlockHeader (os, Ndnb::NDN_DTAG_KeyName, Ndnb::NDN_DTAG); // <KeyName>
          Ndnb::appendName (os, signature.getKeyLocator ().getKeyName ());
          Ndnb::appendCloser (os); // </KeyName>
          break;
        }
      Ndnb::appendCloser (os); // </Signature>
    }
  // other cases should not be possible, but don't do anything
}

void
Ndnb::appendData (std::ostream &os, const Data &data)
{
  if (!data.getSignature ())
    BOOST_THROW_EXCEPTION (error::wire::Ndnb ()
                           << error::msg ("Signature is required, but not set"));

  Ndnb::appendBlockHeader (os, Ndnb::NDN_DTAG_ContentObject, Ndnb::NDN_DTAG); // <ContentObject>

  // necessary for now, because of the changed storage order
  data.getSignature ()->doubleDispatch (os, *this, SIGNATURE_Block);

  Ndnb::appendName (os, data.getName ());

  Ndnb::appendBlockHeader (os, Ndnb::NDN_DTAG_SignedInfo, Ndnb::NDN_DTAG); // <SignedInfo>
  data.getSignature ()->doubleDispatch (os, *this, SINATURE_INFO_PublisherPublicKeyDigest);

  Ndnb::appendTimestampBlob (os, data.getContent ().getTimestamp ());

  BOOST_ASSERT (sizeof (TYPES) == 3 * (static_cast<int> (Content::NACK)+1));
  Ndnb::appendTaggedBlob (os, Ndnb::NDN_DTAG_Type, TYPES [data.getContent ().getType ()], 3);

  if (data.getContent ().getFreshness () != Content::noFreshness)
    {
      Ndnb::appendTaggedNumber (os, Ndnb::NDN_DTAG_FreshnessSeconds,
                                data.getContent ().getFreshness ().total_seconds ());
    }

  if (data.getContent ().getFinalBlockId () != Content::noFinalBlock)
    {
      Ndnb::appendTaggedBlob (os, Ndnb::NDN_DTAG_FinalBlockID, data.getContent ().getFinalBlockId ());
    }

  data.getSignature ()->doubleDispatch (os, *this, SINATURE_INFO_KeyLocator);
  Ndnb::appendCloser (os); // </SignedInfo>

  Ndnb::appendTaggedBlob (os, Ndnb::NDN_DTAG_Content, data.content ());

  Ndnb::appendCloser (os); // </ContentObject>
}

} // namespace wire
} // namespace ndn
