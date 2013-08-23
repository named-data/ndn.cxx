/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "der-printable-string.h"

namespace ndn
{

namespace der
{
  DerPrintableString::DerPrintableString(const string & str)
    :DerByteString(str, DER_PRINTABLE_STRING)
  {}

  DerPrintableString::DerPrintableString(const Blob & blob)
    :DerByteString(blob, DER_PRINTABLE_STRING)
  {}

  DerPrintableString::DerPrintableString(InputIterator &start)
    :DerByteString(start)
  {}

  DerPrintableString::~DerPrintableString()
  {}

}//der

}//ndn
