/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "der-octet-string.h"

namespace ndn
{

namespace der
{
  DerOctetString::DerOctetString(const string & str)
    :DerByteString(str, DER_OCTET_STRING)
  {}

  DerOctetString::DerOctetString(const Blob & blob)
    :DerByteString(blob, DER_OCTET_STRING)
  {}

  DerOctetString::DerOctetString(InputIterator &start)
    :DerByteString(start)
  {}

  DerOctetString::~DerOctetString()
  {}

}//der

}//ndn
