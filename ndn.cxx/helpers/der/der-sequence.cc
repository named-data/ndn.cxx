/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "der-sequence.h"


namespace ndn
{

namespace der
{
  DerSequence::DerSequence ()
    :DerComplex(DER_SEQUENCE)
  {}

  DerSequence::DerSequence (InputIterator &start)
    :DerComplex(start)
  {}

  DerSequence::~DerSequence () 
  {}

}//der

}//ndn
