/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *                     Zhenkai Zhu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 *         Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "closure.h"

namespace ndn {

  Closure::Closure(const DataCallback &dataCallback, 
                   const TimeoutCallback &timeoutCallback,
                   const VerifyFailCallback &verifyFailCallback,
                   const UnverifiedDataCallback &unverifiedDataCallback)
    : m_dataCallback (dataCallback)
    , m_timeoutCallback (timeoutCallback)
    , m_verifyFailCallback (verifyFailCallback)
    , m_unverifiedDataCallback (unverifiedDataCallback)
  {}

  Closure::~Closure ()
  {
  }

} // ndn
