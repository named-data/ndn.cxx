/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "content-type-visitor.h"
#include "../syntax-tree/blob.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

boost::any
ContentTypeVisitor::visit (Blob &n) 
{
  // Buffer n.m_blob;
  if (n.m_blobSize != 3)
    throw NdnbDecodingException ();

  uint32_t type =
    (n.m_blob [0] << 16) |
    (n.m_blob [1] << 8 ) |
    (n.m_blob [2]      );
    
  return boost::any (type);
}

boost::any
ContentTypeVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
  throw NdnbDecodingException ();
}

} // NdnbParser
} // wire

NDN_NAMESPACE_END
