/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "der-bit-string.h"

namespace ndn
{

namespace der
{
  DerBitString::DerBitString(const Blob & blob, uint8_t paddingLen)
    :DerNode(DER_BIT_STRING)
  {     
    m_payload.push_back((char)paddingLen);
    m_payload.insert(m_payload.end(), blob.begin(), blob.end());

    DerNode::encodeHeader(m_payload.size());
  }

  DerBitString::DerBitString(InputIterator &start)
    :DerNode(start)
  {}

  DerBitString::~DerBitString()
  {}

}//der

}//ndn
