/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "der-bool.h"

#include "ndn.cxx/security/exception.h"


namespace ndn
{

namespace der
{
  DerBool::DerBool(bool value)
    :DerNode(DER_BOOLEAN)

  { 
    char payload = (value ? 0xFF : 0x00);
    m_payload.push_back(payload);

    DerNode::encodeHeader(m_payload.size());
  }

  DerBool::DerBool(InputIterator &start)
    :DerNode(start)
  {}

  DerBool::~DerBool()
  {}

}//der

}//ndn
