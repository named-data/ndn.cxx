/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "dattr.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

// dictionary attributes are not used (yet?) in CCNx 
Dattr::Dattr (Buffer::Iterator &start, uint32_t dattr)
{
  m_dattr = dattr;
  m_value = DynamicCast<Udata> (Block::ParseBlock (start));
  if (m_value == 0)
    throw CcnbDecodingException (); // "ATTR must be followed by UDATA field"
}

} // namespace CcnbParser
} // namespace wire

NDN_NAMESPACE_END
