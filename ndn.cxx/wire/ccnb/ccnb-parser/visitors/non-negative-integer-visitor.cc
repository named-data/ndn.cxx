/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "non-negative-integer-visitor.h"

#include "../syntax-tree/blob.h"
#include "../syntax-tree/udata.h"
#include <sstream>

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

boost::any
NonNegativeIntegerVisitor::visit (Blob &n) //to throw parsing error
{
  // Buffer n.m_blob;
  throw CcnbDecodingException ();
}

boost::any
NonNegativeIntegerVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
  std::istringstream is (n.m_udata);
  int32_t value;
  is >> value;
  if (value<0) // value should be non-negative
    throw CcnbDecodingException ();

  return static_cast<uint32_t> (value);
}

} // CcnbParser
} // wire

NDN_NAMESPACE_END
