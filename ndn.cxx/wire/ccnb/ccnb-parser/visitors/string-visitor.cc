/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "string-visitor.h"
#include "../syntax-tree/udata.h"
#include "../syntax-tree/blob.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

boost::any
StringVisitor::visit (Blob &n) 
{
  // Buffer n.m_blob;
  return std::string (n.m_blob, n.m_blobSize);
}

boost::any
StringVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
  return n.m_udata;
}

} // CcnbParser
} // wire

NDN_NAMESPACE_END
