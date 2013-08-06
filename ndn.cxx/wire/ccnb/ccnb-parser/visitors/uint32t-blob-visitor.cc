/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "uint32t-blob-visitor.h"
#include "../syntax-tree/blob.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

boost::any
Uint32tBlobVisitor::visit (Blob &n) 
{
  // Buffer n.m_blob;
  if (n.m_blobSize < 4)
    throw CcnbDecodingException ();
     
  return boost::any (*(reinterpret_cast<uint32_t*> (n.m_blob)));
}

boost::any
Uint32tBlobVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
  throw CcnbDecodingException ();
}

} // CcnbParser
} // wire

NDN_NAMESPACE_END
