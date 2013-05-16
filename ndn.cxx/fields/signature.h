/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_SIGNATURE_H
#define NDN_SIGNATURE_H

namespace ndn {

/**
 * @brief Pure virtual class providing an interface to work with signatures for NDN data packets
 */
class Signature
{
public:
  /**
   * @brief Virtual destructor
   */
  virtual
  ~Signature () { }
};

} // ndn

#endif // NDN_SIGNATURE_H
