/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "der-integer.h"

namespace ndn
{

namespace der
{
  DerInteger::DerInteger(const Blob & blob)
    :DerNode(DER_INTEGER)
  {
    m_payload.insert(m_payload.end(), blob.begin(), blob.end());

    DerNode::encodeHeader(m_payload.size());
  }

  DerInteger::DerInteger(InputIterator &start)
    :DerNode(start)
  {}

  DerInteger::~DerInteger()
  {}

}//der

}//ndn
