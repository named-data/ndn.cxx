/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_BYTE_STRING_H
#define NDN_DER_BYTE_STRING_H

#include "der-node.h"
#include "ndn.cxx/fields/blob.h"

#include <string>

namespace ndn
{

namespace der
{
  class DerByteString : public DerNode
  {
  public:
    DerByteString(const string & str, DerType type);

    DerByteString(const Blob & blob, DerType type);

    DerByteString(InputIterator &start);

    virtual
    ~DerByteString();
  };

}//der

}//ndn

#endif
