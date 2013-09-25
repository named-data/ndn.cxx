/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "closure.h"

namespace ndn {

  Closure::Closure (const DataCallback &dataCallback, 
                    const TimeoutCallback &timeoutCallback, 
                    const UnverifiedCallback &unverifiedCallback,
                    int stepCount)
    : m_dataCallback (dataCallback)
    , m_timeoutCallback (timeoutCallback)
    , m_unverifiedCallback (unverifiedCallback)
    , m_stepCount(stepCount)
  {}

  Closure::~Closure ()
  {}

} // ndn
