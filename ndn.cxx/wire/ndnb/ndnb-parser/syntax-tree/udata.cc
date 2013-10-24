/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "udata.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

Udata::Udata (InputIterator &start, uint32_t length)
{
  // Ideally, the code should look like this. Unfortunately, we don't have normal compatible iterators
  // InputIterator realStart = start;
  // start.Next (length); // advancing forward
  // m_udata.assign (realStart, start/*actually, it is the end*/);

  m_udata.reserve (length+1); //just in case we will need \0 at the end later
  // this is actually the way Read method is implemented in network/src/buffer.cc
  uint32_t i = 0;
  for (; !start.IsEnd () && i < length; i++)
    {
      m_udata.push_back (start.ReadU8 ());
    }

  if (i < length && start.IsEnd ())
    throw NdnbDecodingException ();
}

} // namespace NdnbParser
} // namespace wire

NDN_NAMESPACE_END
