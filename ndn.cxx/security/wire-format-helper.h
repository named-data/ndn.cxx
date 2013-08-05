/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_WIRE_HELPER_H
#define NDN_WIRE_HELPER_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/data.h"

namespace ndn
{

namespace security
{

  class Wire
  {
  public:
    static Ptr<Blob> 
    toUnsignedWire(const Data & data);
  };

}//security

}//ndn

#endif
