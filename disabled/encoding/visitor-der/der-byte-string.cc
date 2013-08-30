/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "der-byte-string.h"

namespace ndn
{

namespace der
{
  DerByteString::DerByteString(const string & str, DerType type)
    :DerNode(type)
  {
    m_payload.insert(m_payload.end(), str.begin(), str.end());

    DerNode::encodeHeader(m_payload.size());
  }

  DerByteString::DerByteString(const Blob & blob, DerType type)
    :DerNode(type)
  {
    m_payload.insert(m_payload.end(), blob.begin(), blob.end());

    DerNode::encodeHeader(m_payload.size());
  }

  DerByteString::DerByteString(InputIterator &start)
    :DerNode(start)
  {}

  DerByteString::~DerByteString()
  {}

}//der

}//ndn

