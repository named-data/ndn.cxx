/** -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/* 
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 * 
 * BSD license, See the doc/LICENSE file for more information
 * 
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_WIRE_CCNB_DATA_H
#define NDN_WIRE_CCNB_DATA_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/data.h"
#include "ndn.cxx/fields/content.h"

NDN_NAMESPACE_BEGIN

namespace wire {

/**
 * @brief Namespace for CCNb wire format operations
 */
namespace ccnb {

/**
  * @brief Routines to serialize/deserialize NDN data in ccnb format
  *
  * @see http://www.ccnx.org/releases/latest/doc/technical/BinaryEncoding.html
  **/
class Data
{
public:
  static void
  Serialize (const ndn::Data &data, OutputIterator &start);

  static void 
  SerializeUnsigned (const ndn::Data &data, OutputIterator &start);

  static void
  Deserialize (Ptr<ndn::Data> data, InputIterator &start);

  static ndn::Content::Type
  toType(uint32_t typeBytes);
};



} //ccnb
} //wire

NDN_NAMESPACE_END

#endif

