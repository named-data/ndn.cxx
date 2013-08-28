/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_WIRE_CCNB_H
#define NDN_WIRE_CCNB_H

#include "base.h"

#include "ndn.cxx/interest.h"
#include "ndn.cxx/data.h"

namespace ndn {
namespace wire {

/**
 * @brief Class for working with ccnb encoding
 */
class Ccnb : public Base
{
public:
  /**
   * \brief Type tag for a ccnb start marker.
   *
   * \see http://www.ccnx.org/releases/latest/doc/technical/DTAG.html
   */
  enum ccn_tt {
    NDN_EXT,        /**< starts composite extension - numval is subtype */
    NDN_TAG,        /**< starts composite - numval is tagnamelen-1 */
    NDN_DTAG,       /**< starts composite - numval is tagdict index (enum ccn_dtag) */
    NDN_ATTR,       /**< attribute - numval is attrnamelen-1, value follows */
    NDN_DATTR,      /**< attribute numval is attrdict index */
    NDN_BLOB,       /**< opaque binary data - numval is byte count */
    NDN_UDATA,      /**< UTF-8 encoded character data - numval is byte count */
    NDN_NO_TOKEN    /**< should not occur in encoding */
  };

  /** \brief NDN_CLOSE_TAG terminates composites */
  enum {NDN_CLOSE_TAG = 0};

  /**
   * \brief DTAG identifies ccnb-encoded elements.
   *
   * \see http://www.ccnx.org/releases/latest/doc/technical/DTAG.html
   */
  enum ccn_dtag {
    NDN_DTAG_Any = 13,
    NDN_DTAG_Name = 14,
    NDN_DTAG_Component = 15,
    NDN_DTAG_Certificate = 16,
    NDN_DTAG_Collection = 17,
    NDN_DTAG_CompleteName = 18,
    NDN_DTAG_Content = 19,
    NDN_DTAG_SignedInfo = 20,
    NDN_DTAG_ContentDigest = 21,
    NDN_DTAG_ContentHash = 22,
    NDN_DTAG_Count = 24,
    NDN_DTAG_Header = 25,
    NDN_DTAG_Interest = 26,	/* 20090915 */
    NDN_DTAG_Key = 27,
    NDN_DTAG_KeyLocator = 28,
    NDN_DTAG_KeyName = 29,
    NDN_DTAG_Length = 30,
    NDN_DTAG_Link = 31,
    NDN_DTAG_LinkAuthenticator = 32,
    NDN_DTAG_NameComponentCount = 33,	/* DeprecatedInInterest */
    NDN_DTAG_RootDigest = 36,
    NDN_DTAG_Signature = 37,
    NDN_DTAG_Start = 38,
    NDN_DTAG_Timestamp = 39,
    NDN_DTAG_Type = 40,
    NDN_DTAG_Nonce = 41,
    NDN_DTAG_Scope = 42,
    NDN_DTAG_Exclude = 43,
    NDN_DTAG_Bloom = 44,
    NDN_DTAG_BloomSeed = 45,
    NDN_DTAG_AnswerOriginKind = 47,
    NDN_DTAG_InterestLifetime = 48,
    NDN_DTAG_Witness = 53,
    NDN_DTAG_SignatureBits = 54,
    NDN_DTAG_DigestAlgorithm = 55,
    NDN_DTAG_BlockSize = 56,
    NDN_DTAG_FreshnessSeconds = 58,
    NDN_DTAG_FinalBlockID = 59,
    NDN_DTAG_PublisherPublicKeyDigest = 60,
    NDN_DTAG_PublisherCertificateDigest = 61,
    NDN_DTAG_PublisherIssuerKeyDigest = 62,
    NDN_DTAG_PublisherIssuerCertificateDigest = 63,
    NDN_DTAG_ContentObject = 64,	/* 20090915 */
    NDN_DTAG_WrappedKey = 65,
    NDN_DTAG_WrappingKeyIdentifier = 66,
    NDN_DTAG_WrapAlgorithm = 67,
    NDN_DTAG_KeyAlgorithm = 68,
    NDN_DTAG_Label = 69,
    NDN_DTAG_EncryptedKey = 70,
    NDN_DTAG_EncryptedNonceKey = 71,
    NDN_DTAG_WrappingKeyName = 72,
    NDN_DTAG_Action = 73,
    NDN_DTAG_FaceID = 74,
    NDN_DTAG_IPProto = 75,
    NDN_DTAG_Host = 76,
    NDN_DTAG_Port = 77,
    NDN_DTAG_MulticastInterface = 78,
    NDN_DTAG_ForwardingFlags = 79,
    NDN_DTAG_FaceInstance = 80,
    NDN_DTAG_ForwardingEntry = 81,
    NDN_DTAG_MulticastTTL = 82,
    NDN_DTAG_MinSuffixComponents = 83,
    NDN_DTAG_MaxSuffixComponents = 84,
    NDN_DTAG_ChildSelector = 85,
    NDN_DTAG_RepositoryInfo = 86,
    NDN_DTAG_Version = 87,
    NDN_DTAG_RepositoryVersion = 88,
    NDN_DTAG_GlobalPrefix = 89,
    NDN_DTAG_LocalName = 90,
    NDN_DTAG_Policy = 91,
    NDN_DTAG_Namespace = 92,
    NDN_DTAG_GlobalPrefixName = 93,
    NDN_DTAG_PolicyVersion = 94,
    NDN_DTAG_KeyValueSet = 95,
    NDN_DTAG_KeyValuePair = 96,
    NDN_DTAG_IntegerValue = 97,
    NDN_DTAG_DecimalValue = 98,
    NDN_DTAG_StringValue = 99,
    NDN_DTAG_BinaryValue = 100,
    NDN_DTAG_NameValue = 101,
    NDN_DTAG_Entry = 102,
    NDN_DTAG_ACL = 103,
    NDN_DTAG_ParameterizedName = 104,
    NDN_DTAG_Prefix = 105,
    NDN_DTAG_Suffix = 106,
    NDN_DTAG_Root = 107,
    NDN_DTAG_ProfileName = 108,
    NDN_DTAG_Parameters = 109,
    NDN_DTAG_InfoString = 110,
    NDN_DTAG_StatusResponse = 112,
    NDN_DTAG_StatusCode = 113,
    NDN_DTAG_StatusText = 114,
    NDN_DTAG_Nack = 200,
    NDN_DTAG_SequenceNumber = 256,
    NDN_DTAG_CCNProtocolDataUnit = 17702112
  };


  /**
   * @brief Append CCNB block header
   * @param os output stream to write
   * @param value dictionary id of the block header
   * @param block_type Type of CCNB block
   */
  static void
  appendBlockHeader (std::ostream &os, size_t value, ccn_tt block_type);

  /**
   * @brief Add number in CCNB encoding
   * @param os output stream to write
   * @param number Number to be written
   *
   * @returns written length
   */
  static void
  appendNumber (std::ostream &os, uint32_t number);

  /**
   * @brief Append CCNB closer tag (size is 1)
   * @param os output stream to write
   */
  inline static void
  appendCloser (std::ostream &os);

  /**
   * @brief Append Name in CCNB encoding
   * @param os output stream to write
   * @param name constant reference to Name object
   *
   * @returns written length
   */
  static void
  appendName (std::ostream &os, const Name &name);

  /**
   * Append a binary timestamp as a BLOB using the ccn binary
   * Timestamp representation (12-bit fraction).
   *
   * @param os output stream to write
   * @param time reference to time duration object
   */
  static void
  appendTimestampBlob (std::ostream &os, const TimeInterval &timestamp);

  /**
   * Append a binary timestamp as a BLOB using the ccn binary
   * Timestamp representation (12-bit fraction).
   *
   * @param os output stream to write
   * @param time reference to Time (posix_time::ptime) object.
   *             This method automatically calculates duration between time and gregorian::date(1970,1,1)
   *             and calls the other version of the method
   */
  inline static void
  appendTimestampBlob (std::ostream &os, const Time &time);

  /**
   * Append a tagged BLOB
   *
   * This is a ccnb-encoded element with containing the BLOB as content
   *
   * @param os output stream to write
   * @param dtag is the element's dtag
   * @param data points to the binary data
   * @param size is the size of the data, in bytes
   */
  inline static void
  appendTaggedBlob (std::ostream &os, ccn_dtag dtag, const void *data, size_t size);

  /**
   * Append a tagged BLOB
   *
   * This is a ccnb-encoded element with containing the BLOB as content
   *
   * @param os output stream to write
   * @param dtag is the element's dtag
   * @param blob reference to the data blob
   */
  inline static void
  appendTaggedBlob (std::ostream &os, ccn_dtag dtag, const Blob &blob);

  /**
   * Append a tagged BLOB
   *
   * This is a ccnb-encoded element with containing the BLOB as content
   *
   * @param os output stream to write
   * @param dtag is the element's dtag
   * @param data points to the binary data
   * @param size is the size of the data, in bytes
   */
  inline static void
  appendTaggedNumber (std::ostream &os, ccn_dtag dtag, uint32_t number);

  /**
   * Append a tagged string (should be a valid UTF-8 coded string)
   *
   * This is a ccnb-encoded element with containing UDATA as content
   *
   * @param os output stream to write
   * @param dtag is the element's dtag
   * @param string UTF-8 string to be written
   */
  inline static void
  appendString (std::ostream &os, ccn_dtag dtag, const std::string &string);

  /**
   * @brief Format interest in CCNb encoding
   * @param os output stream to write
   * @param interest Interest to be formatted
   *
   * @todo For now, this method is used to create Interest template, which doesn't output name to the stream
   */
  static void
  appendInterest (std::ostream &os, const Interest &interest);

  /**
   * @brief Append exclude filter in CCNb encoding
   * @param os output stream to write
   * @param exclude Exclude filter to be formatted
   */
  static void
  appendExclude (std::ostream &os, const Exclude &exclude);

  /**
   * @brief Append signature in SHA256withRSA format
   */
  virtual void
  appendSignature (std::ostream &os, const signature::Sha256WithRsa &signature, void *userData);

  /**
   * @brief Format data in CCNb encoding
   * @param os output stream to write
   * @param data data to be formatted
   */
  void
  appendData (std::ostream &os, const Data &data);
};


inline void
Ccnb::appendCloser (std::ostream &os)
{
  os.put (Ccnb::NDN_CLOSE_TAG);
}

inline void
Ccnb::appendTimestampBlob (std::ostream &os, const Time &time)
{
  appendTimestampBlob (os, time - time::UNIX_EPOCH_TIME);
}

inline void
Ccnb::appendTaggedBlob (std::ostream &os, Ccnb::ccn_dtag dtag, const void *data, size_t size)
{
  appendBlockHeader (os, dtag, Ccnb::NDN_DTAG);
  /* 2 */
  if (size>0)
    {
      appendBlockHeader (os, size, Ccnb::NDN_BLOB);
      os.write (reinterpret_cast<const char*> (data), size);
      /* size */
    }
  appendCloser (os);
  /* 1 */
}

inline void
Ccnb::appendTaggedBlob (std::ostream &os, ccn_dtag dtag, const Blob &blob)
{
  appendTaggedBlob (os, dtag, blob.buf (), blob.size ());
}

inline void
Ccnb::appendTaggedNumber (std::ostream &os, Ccnb::ccn_dtag dtag, uint32_t number)
{
  appendBlockHeader (os, dtag, Ccnb::NDN_DTAG);
  {
    appendNumber (os, number);
  }
  appendCloser (os);
}

inline void
Ccnb::appendString (std::ostream &os, Ccnb::ccn_dtag dtag, const std::string &string)
{
  appendBlockHeader (os, dtag, Ccnb::NDN_DTAG);
  {
    appendBlockHeader (os, string.size (), Ccnb::NDN_UDATA);
    os.write (string.c_str (), string.size ());
  }
  appendCloser (os);
}

} // wire
} // ndn

#endif // NDN_WIRE_CCNB_H
