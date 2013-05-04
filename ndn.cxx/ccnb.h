/* -*- Mode: C++; c-file-style: "gnu"; tab-width: 4; indent-tabs-mode:nil; -*- */
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
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_CCNB_H
#define NDN_CCNB_H

#include <ndn.cxx/name.h>
#include <boost/date_time/posix_time/posix_time_types.hpp>

#ifdef NDN_DETAIL_NEED_UNDEFINE_CCN_CLOSE
#undef CCN_CLOSE
#endif

namespace ndn
{

/**
 * @brief Class for working with ccnb encoding
 */
class Ccnb
{
public:
  /**
   * \brief Type tag for a ccnb start marker.
   *
   * \see http://www.ccnx.org/releases/latest/doc/technical/DTAG.html
   */
  enum ccn_tt {
    CCN_EXT,        /**< starts composite extension - numval is subtype */
    CCN_TAG,        /**< starts composite - numval is tagnamelen-1 */ 
    CCN_DTAG,       /**< starts composite - numval is tagdict index (enum ccn_dtag) */
    CCN_ATTR,       /**< attribute - numval is attrnamelen-1, value follows */
    CCN_DATTR,      /**< attribute numval is attrdict index */
    CCN_BLOB,       /**< opaque binary data - numval is byte count */
    CCN_UDATA,      /**< UTF-8 encoded character data - numval is byte count */
    CCN_NO_TOKEN    /**< should not occur in encoding */
  };

#ifndef CCN_CLOSE
  /** \brief CCN_CLOSE terminates composites */
  enum {CCN_CLOSE = 0};
#endif  

  /**
   * \brief DTAG identifies ccnb-encoded elements.
   *
   * \see http://www.ccnx.org/releases/latest/doc/technical/DTAG.html
   */
  enum ccn_dtag {
    CCN_DTAG_Any = 13,
    CCN_DTAG_Name = 14,
    CCN_DTAG_Component = 15,
    CCN_DTAG_Certificate = 16,
    CCN_DTAG_Collection = 17,
    CCN_DTAG_CompleteName = 18,
    CCN_DTAG_Content = 19,
    CCN_DTAG_SignedInfo = 20,
    CCN_DTAG_ContentDigest = 21,
    CCN_DTAG_ContentHash = 22,
    CCN_DTAG_Count = 24,
    CCN_DTAG_Header = 25,
    CCN_DTAG_Interest = 26,	/* 20090915 */
    CCN_DTAG_Key = 27,
    CCN_DTAG_KeyLocator = 28,
    CCN_DTAG_KeyName = 29,
    CCN_DTAG_Length = 30,
    CCN_DTAG_Link = 31,
    CCN_DTAG_LinkAuthenticator = 32,
    CCN_DTAG_NameComponentCount = 33,	/* DeprecatedInInterest */
    CCN_DTAG_RootDigest = 36,
    CCN_DTAG_Signature = 37,
    CCN_DTAG_Start = 38,
    CCN_DTAG_Timestamp = 39,
    CCN_DTAG_Type = 40,
    CCN_DTAG_Nonce = 41,
    CCN_DTAG_Scope = 42,
    CCN_DTAG_Exclude = 43,
    CCN_DTAG_Bloom = 44,
    CCN_DTAG_BloomSeed = 45,
    CCN_DTAG_AnswerOriginKind = 47,
    CCN_DTAG_InterestLifetime = 48,
    CCN_DTAG_Witness = 53,
    CCN_DTAG_SignatureBits = 54,
    CCN_DTAG_DigestAlgorithm = 55,
    CCN_DTAG_BlockSize = 56,
    CCN_DTAG_FreshnessSeconds = 58,
    CCN_DTAG_FinalBlockID = 59,
    CCN_DTAG_PublisherPublicKeyDigest = 60,
    CCN_DTAG_PublisherCertificateDigest = 61,
    CCN_DTAG_PublisherIssuerKeyDigest = 62,
    CCN_DTAG_PublisherIssuerCertificateDigest = 63,
    CCN_DTAG_ContentObject = 64,	/* 20090915 */
    CCN_DTAG_WrappedKey = 65,
    CCN_DTAG_WrappingKeyIdentifier = 66,
    CCN_DTAG_WrapAlgorithm = 67,
    CCN_DTAG_KeyAlgorithm = 68,
    CCN_DTAG_Label = 69,
    CCN_DTAG_EncryptedKey = 70,
    CCN_DTAG_EncryptedNonceKey = 71,
    CCN_DTAG_WrappingKeyName = 72,
    CCN_DTAG_Action = 73,
    CCN_DTAG_FaceID = 74,
    CCN_DTAG_IPProto = 75,
    CCN_DTAG_Host = 76,
    CCN_DTAG_Port = 77,
    CCN_DTAG_MulticastInterface = 78,
    CCN_DTAG_ForwardingFlags = 79,
    CCN_DTAG_FaceInstance = 80,
    CCN_DTAG_ForwardingEntry = 81,
    CCN_DTAG_MulticastTTL = 82,
    CCN_DTAG_MinSuffixComponents = 83,
    CCN_DTAG_MaxSuffixComponents = 84,
    CCN_DTAG_ChildSelector = 85,
    CCN_DTAG_RepositoryInfo = 86,
    CCN_DTAG_Version = 87,
    CCN_DTAG_RepositoryVersion = 88,
    CCN_DTAG_GlobalPrefix = 89,
    CCN_DTAG_LocalName = 90,
    CCN_DTAG_Policy = 91,
    CCN_DTAG_Namespace = 92,
    CCN_DTAG_GlobalPrefixName = 93,
    CCN_DTAG_PolicyVersion = 94,
    CCN_DTAG_KeyValueSet = 95,
    CCN_DTAG_KeyValuePair = 96,
    CCN_DTAG_IntegerValue = 97,
    CCN_DTAG_DecimalValue = 98,
    CCN_DTAG_StringValue = 99,
    CCN_DTAG_BinaryValue = 100,
    CCN_DTAG_NameValue = 101,
    CCN_DTAG_Entry = 102,
    CCN_DTAG_ACL = 103,
    CCN_DTAG_ParameterizedName = 104,
    CCN_DTAG_Prefix = 105,
    CCN_DTAG_Suffix = 106,
    CCN_DTAG_Root = 107,
    CCN_DTAG_ProfileName = 108,
    CCN_DTAG_Parameters = 109,
    CCN_DTAG_InfoString = 110,
    CCN_DTAG_StatusResponse = 112,
    CCN_DTAG_StatusCode = 113,
    CCN_DTAG_StatusText = 114,
    CCN_DTAG_Nack = 200,
    CCN_DTAG_SequenceNumber = 256,
    CCN_DTAG_CCNProtocolDataUnit = 17702112
  };


  /**
   * @brief Append CCNB block header
   * @param os output stream to write
   * @param value dictionary id of the block header
   * @param block_type Type of CCNB block
   *
   * @returns written length
   */
  static size_t
  AppendBlockHeader (std::ostream &os, size_t value, ccn_tt block_type);

  /**
   * @brief Add number in CCNB encoding
   * @param os output stream to write
   * @param number Number to be written
   *
   * @returns written length
   */
  static size_t
  AppendNumber (std::ostream &os, uint32_t number);

  /**
   * @brief Append CCNB closer tag (size is 1)
   * @param os output stream to write
   *
   * @returns written length
   */
  static size_t
  AppendCloser (std::ostream &os);

  /**
   * @brief Append Name in CCNB encoding
   * @param os output stream to write
   * @param name constant reference to Name object
   *
   * @returns written length
   */
  static size_t
  AppendName (std::ostream &os, const Name &name);

  /**
   * Append a binary timestamp as a BLOB using the ccn binary
   * Timestamp representation (12-bit fraction).
   *
   * @param os output stream to write
   * @param time reference to time duration object
   *
   * @returns written length
   */
  static size_t
  AppendTimestampBlob (std::ostream &os, const boost::posix_time::time_duration &time);

  /**
   * Append a tagged BLOB
   *
   * This is a ccnb-encoded element with containing the BLOB as content
   *
   * @param os output stream to write
   * @param dtag is the element's dtag
   * @param data points to the binary data
   * @param size is the size of the data, in bytes
   *
   * @returns written length
   */
  static size_t
  AppendTaggedBlob (std::ostream &os, ccn_dtag dtag, const uint8_t *data, size_t size);
  
  /**
   * Append value as a tagged BLOB (templated version)
   *
   * This is a ccnb-encoded element with containing the BLOB as content
   *
   * Data will be reinterpret_cast<const uint8_t*> and size will be obtained using sizeof
   *
   * @param os output stream to write
   * @param dtag is the element's dtag
   * @param data a value to add
   *
   * @returns written length
   */
  template<class T>
  static inline size_t
  AppendTaggedBlob (std::ostream &os, ccn_dtag dtag, const T &data)
  {
    return AppendTaggedBlob (os, dtag, reinterpret_cast<const uint8_t*> (&data), sizeof (data));
  }

  /**
   * Append a tagged string (should be a valid UTF-8 coded string)
   *
   * This is a ccnb-encoded element with containing UDATA as content
   *
   * @param start start iterator of  the buffer to append to.
   * @param dtag is the element's dtag
   * @param string UTF-8 string to be written
   *
   * @returns written length
   */
  static size_t
  AppendString (std::ostream &os, ccn_dtag dtag, const std::string &string);
};
  
} // ndn

#endif // NDN_CCNB_H
