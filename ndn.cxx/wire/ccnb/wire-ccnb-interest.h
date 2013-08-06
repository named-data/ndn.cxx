/** -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/* 
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 * 
 * BSD license, See the doc/LICENSE file for more information
 * 
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_WIRE_CCNB_INTEREST_H
#define NDN_WIRE_CCNB_INTEREST_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/interest.h"
#include "ndn.cxx/data.h"

NDN_NAMESPACE_BEGIN

namespace wire {

/**
 * @brief Namespace for CCNb wire format operations
 */
namespace ccnb {

/**
  * @brief Routines to serialize/deserialize NDN interest in ccnb format
  *
  * @see http://www.ccnx.org/releases/latest/doc/technical/BinaryEncoding.html
  **/
class Interest
{
public:
  static void
  Serialize (const ndn::Interest &interest, OutputIterator &start);

  static void
  Deserialize (Ptr<ndn::Interest> interest, InputIterator &start);
};

} // ccnb
} // wire

NDN_NAMESPACE_END

#endif // NDN_WIRE_CCNB_INTEREST_H
