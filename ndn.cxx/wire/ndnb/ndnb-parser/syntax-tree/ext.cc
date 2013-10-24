/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "ext.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

Ext::Ext (InputIterator &start, uint32_t extSubtype)
{
  m_extSubtype = extSubtype;
}

} // namespace NdnbParser
} // namespace wire

NDN_NAMESPACE_END
