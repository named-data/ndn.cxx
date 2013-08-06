/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "timestamp-visitor.h"
#include "../syntax-tree/blob.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

boost::any/*Time*/
TimestampVisitor::visit (Blob &n) 
{
  // Buffer n.m_blob;
  if (n.m_blobSize < 2)
    throw CcnbDecodingException ();

  const char *start = n.m_blob;
  
  int seconds = 0;
  int nanoseconds = 0;

  for (uint32_t i=0; i < n.m_blobSize-2; i++)
    {
      seconds = (seconds << 8) | (uint8_t)start[i];
    }
  uint8_t combo = start[n.m_blobSize-2]; // 4 most significant bits hold 4 least significant bits of number of seconds
  seconds = (seconds << 4) | (combo >> 4);

  nanoseconds = combo & 0x0F; /*00001111*/ // 4 least significant bits hold 4 most significant bits of number of
  nanoseconds = (nanoseconds << 8) | start[n.m_blobSize-1];
  nanoseconds = (intmax_t) ((nanoseconds / 4096.0/*2^12*/) * 1000000 /*up-convert useconds*/);

  return boost::any (time::Seconds (seconds) + time::Microseconds (nanoseconds/1000));
}

boost::any
TimestampVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
  throw CcnbDecodingException ();
}

} // CcnbParser
} // wire

NDN_NAMESPACE_END
