/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CLOSURE_H
#define NDN_CLOSURE_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/name.h"
#include "ndn.cxx/interest.h"
#include "ndn.cxx/data.h"

namespace ndn {

  class Closure;

  typedef boost::function<void (Ptr<Data>)> DataCallback;
  typedef boost::function<void (Ptr<Closure>, Ptr<Interest>)> TimeoutCallback;
  typedef boost::function<void (Ptr<Data>)> UnverifiedCallback;

  class Closure
  {
  public:    
    Closure(const DataCallback& dataCallback, 
            const TimeoutCallback& timeoutCallback, 
            const UnverifiedCallback& unverifiedCallback,
            int stepCount = 0);

    virtual 
    ~Closure();
    
        
  public:
    DataCallback m_dataCallback;
    TimeoutCallback m_timeoutCallback;
    UnverifiedCallback m_unverifiedCallback;
    int m_stepCount;

  };

} // ndn

#endif
