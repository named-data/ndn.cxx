/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "blob.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

Blob::Blob (InputIterator &start, uint32_t length)
{
  m_blobSize = length;
  m_blob = new char[length];
  if (m_blob == 0 )
    throw NdnbDecodingException (); // memory problem

  uint32_t i = 0;
  for (; !start.IsEnd () && i < length; i++)
    {
      m_blob[i] = start.ReadU8 ();
    }
  if (i < length && start.IsEnd ())
    throw NdnbDecodingException ();
  // Block::counter += length;
}

Blob::~Blob ()
{
  delete [] m_blob;
}

} // namespace NdnbParser
} // namespace wire

NDN_NAMESPACE_END
