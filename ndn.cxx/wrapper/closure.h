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

#ifndef NDN_CLOSURE_H
#define NDN_CLOSURE_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/name.h"
#include "ndn.cxx/interest.h"

namespace ndn {

  class Data;

  class Closure
  {
  public:

    typedef boost::function<void (Ptr<Data>)> DataCallback;
    typedef boost::function<void (Ptr<Closure>, Ptr<Interest>)> TimeoutCallback;
    typedef boost::function<void (Ptr<Interest>)> VerifyFailCallback;
    typedef boost::function<void (Ptr<Data>)> UnverifiedDataCallback;
    
    Closure(const DataCallback &dataCallback, 
            const TimeoutCallback &timeoutCallback = TimeoutCallback(), 
            const VerifyFailCallback &verifyFailCallback = VerifyFailCallback(),
            const UnverifiedDataCallback &unverifiedDataCallback = UnverifiedDataCallback());

    virtual ~Closure();
        
    virtual Closure *
    dup () const { return new Closure (*this); }

  public:
    DataCallback m_dataCallback;
    TimeoutCallback m_timeoutCallback;
    VerifyFailCallback m_verifyFailCallback;
    UnverifiedDataCallback m_unverifiedDataCallback;

  };

} // ndn

#endif
