/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_WIRE_NDNB_SYNTAX_H
#define NDN_WIRE_NDNB_SYNTAX_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/name.h"

NDN_NAMESPACE_BEGIN

namespace wire {

/**
 * \brief Helper to encode NDNb blocks
 */
class Ndnb
{
public:
  /**
   * @brief Append NDNB block header
   * @param start Buffer to store serialized
   * @param value dictionary id of the block header
   * @param block_type Type of NDNB block
   *
   * @returns written length
   */
  static size_t
  AppendBlockHeader (OutputIterator &start, size_t value, uint32_t block_type);

  /**
   * @brief Estimate size of the NDNB block header
   * @param value dictionary id of the block header
   * @returns estimated length
   */
  static size_t
  EstimateBlockHeader (size_t value);

  /**
   * @brief Add number in NDNB encoding
   * @param start Buffer to store serialized NdnInterest
   * @param number Number to be written
   *
   * @returns written length
   */
  static size_t
  AppendNumber (OutputIterator &start, uint32_t number);

  /**
   * @brief Estimate size of the number in NDNB encoding
   * @param number Number to be written
   * @returns estimated length
   */
  static size_t
  EstimateNumber (uint32_t number);

  /**
   * @brief Append NDNB closer tag (estimated size is 1)
   * @param start Buffer to store serialized Interest
   *
   * @returns written length
   */
  static size_t
  AppendCloser (OutputIterator &start);

  /**
   * Append a binary timestamp as a BLOB using the ndn binary
   * Timestamp representation (12-bit fraction).
   *
   * @param start start iterator of  the buffer to append to.
   * @param time - Time object
   *
   * @returns written length
   */
  static size_t
  AppendTimestampBlob (OutputIterator &start, const TimeInterval &time);

  /**
   * @brief Estimate size of a binary timestamp as a BLOB using NDNB enconding
   * @param time - Time object
   * @returns estimated length
   */
  static size_t
  EstimateTimestampBlob (const TimeInterval &time);
  
   /**
   * Append a binary timestamp as a BLOB using the ndn binary
   * Timestamp representation (12-bit fraction).
   *
   * @param os output stream to write
   * @param time reference to Time (posix_time::ptime) object.
   *             This method automatically calculates duration between time and gregorian::date(1970,1,1)
   *             and calls the other version of the method
   */
  inline static void
  AppendTimestampBlob (std::ostream &os, const Time &time);

  /**
   * @brief Estimate size of a binary timestamp as a BLOB using NDNB enconding
   * @param time - Time object
   * @returns estimated length
   */
  static size_t
  EstimateTimestampBlob (const Time &time);
  
  /**
   * Append a tagged BLOB
   *
   * This is a ndnb-encoded element with containing the BLOB as content
   *
   * @param start start iterator of  the buffer to append to.
   * @param dtag is the element's dtab
   * @param data points to the binary data
   * @param size is the size of the data, in bytes
   *
   * @returns written length
   */
  static size_t
  AppendTaggedBlob (OutputIterator &start, uint32_t dtag,
                    const uint8_t *data, size_t size);
  
  /**
   * Append a tagged BLOB, adding 0-byte padding if necessary
   *
   * This is a ndnb-encoded element with containing the BLOB as content
   *
   * @param start start iterator of  the buffer to append to.
   * @param dtag is the element's dtab
   * @param length minimum required length of the added field (padding added if necessary)
   * @param data points to the binary data
   * @param size is the size of the data, in bytes
   *
   * @returns written length
   */
  static size_t
  AppendTaggedBlobWithPadding (OutputIterator &start, uint32_t dtag,
                               uint32_t length,
                               const uint8_t *data, size_t size);

  /**
   * @brief Estimate size of a tagged BLOB in NDNB enconding
   * @param dtag is the element's dtab
   * @param size is the size of the data, in bytes
   * @returns estimated length
   */
  static size_t
  EstimateTaggedBlob (uint32_t dtag, size_t size);

  /**
   * Append value as a tagged BLOB (templated version)
   *
   * This is a ndnb-encoded element with containing the BLOB as content
   *
   * Data will be reinterpret_cast<const uint8_t*> and size will be obtained using sizeof
   *
   * @param start start iterator of  the buffer to append to.
   * @param dtag is the element's dtab
   * @param data a value to add
   *
   * @returns written length
   */
  template<class T>
  static inline size_t
  AppendTaggedBlob (OutputIterator &start, uint32_t dtag, const T &data);

  /**
   * Append value as a tagged BLOB (templated version), add 0-padding if necessary
   *
   * This is a ndnb-encoded element with containing the BLOB as content
   *
   * Data will be reinterpret_cast<const uint8_t*> and size will be obtained using sizeof
   *
   * @param start start iterator of  the buffer to append to.
   * @param dtag is the element's dtab
   * @param length minimum required length of the field
   * @param data a value to add
   *
   * @returns written length
   */
  template<class T>
  static inline size_t
  AppendTaggedBlobWithPadding (OutputIterator &start, uint32_t dtag, uint32_t length, const T &data);

  /**
   * Append a tagged string (should be a valid UTF-8 coded string)
   *
   * This is a ndnb-encoded element with containing UDATA as content
   *
   * @param start start iterator of  the buffer to append to.
   * @param dtag is the element's dtab
   * @param string UTF-8 string to be written
   *
   * @returns written length
   */
  static size_t
  AppendString (OutputIterator &start, uint32_t dtag,
                const std::string &string);

  /**
   * @brief Estimate size of the string in NDNB encoding
   * @param dtag is the element's dtab
   * @param string UTF-8 string to be written
   * @returns estimated length
   */
  static size_t
  EstimateString (uint32_t dtag, const std::string &string);

  /**
   * Append a tagged BLOB
   *
   * This is a ndnb-encoded element with containing the BLOB as content
   *
   * @param os output stream to write
   * @param dtag is the element's dtag
   * @param data points to the binary data
   * @param size is the size of the data, in bytes
   */
  static void
  AppendTaggedNumber (OutputIterator &os, uint32_t dtag, uint32_t number);
  
  ////////////////////////////////
  // General use wire formatters
  ////////////////////////////////
  
  /**
   * @brief Append Name in NDNB encoding
   * @param start Buffer to store serialized Interest
   * @param name constant reference to Name object
   *
   * @returns written length
   */
  static size_t
  SerializeName (OutputIterator &start, const Name &name);

  /**
   * @brief Estimate size of Name in NDNB encoding
   * @param name constant reference to Name object
   * @returns estimated length
   */
  static size_t
  SerializedSizeName (const Name &name);

  /**
   * @brief Deserialize Name from NDNB encodeing
   * @param start Buffer that stores serialized Interest
   * @param name Name object
   */
  static Ptr<Name>
  DeserializeName (InputIterator &start);
}; // Ndnb


template<class T>
inline size_t
Ndnb::AppendTaggedBlob (OutputIterator &start, uint32_t dtag, const T &data)
{
  return AppendTaggedBlob (start, dtag, reinterpret_cast<const uint8_t*> (&data), sizeof (data));
}

template<class T>
inline size_t
Ndnb::AppendTaggedBlobWithPadding (OutputIterator &start, uint32_t dtag, uint32_t length, const T &data)
{
  return AppendTaggedBlobWithPadding (start, dtag, length, reinterpret_cast<const uint8_t*> (&data), sizeof (data));
}

} // wire

NDN_NAMESPACE_END

#endif // NDN_WIRE_NDNB_SYNTAX_H
