/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "der-null.h"

namespace ndn
{

namespace der
{
  DerNull::DerNull()
    :DerNode(DER_NULL)
  {
    DerNode::encodeHeader(0);
  }
  
  DerNull::DerNull(InputIterator & start)
    :DerNode(start)
  {}
    
  DerNull::~DerNull()
  {}

}//der

}//ndn
