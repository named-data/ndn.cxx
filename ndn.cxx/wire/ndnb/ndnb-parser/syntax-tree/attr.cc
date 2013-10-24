/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "attr.h"
#include "../common.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

// length length in octets of UTF-8 encoding of tag name - 1 (minimum tag name length is 1) 
Attr::Attr (InputIterator &start, uint32_t length)
{
  m_attr.reserve (length+2); // extra byte for potential \0 at the end
  uint32_t i = 0;
  for (; !start.IsEnd () && i < (length+1); i++)
    {
      m_attr.push_back (start.ReadU8 ());
    }
  if (i < (length+1) && start.IsEnd ())
    throw NdnbDecodingException ();
  m_value = DynamicCast<Udata> (Block::ParseBlock (start));
  if (m_value == 0)
    throw NdnbDecodingException (); // "ATTR must be followed by UDATA field"
}

} // namespace NdnbParser
} // namespace wire

NDN_NAMESPACE_END
