/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_FAKE_WRAPPER_H
#define NDN_FAKE_WRAPPER_H

#include "ndn.cxx/common.h"
#include "closure.h"


class Executor;

namespace ndn
{
  namespace security
  {
    class Keychain;
  }

  class FakeWrapper
  {
  public:
    FakeWrapper(Ptr<security::Keychain> keychain);
    
    ~FakeWrapper();

    void 
    sendInterest(Ptr<Interest> interestPtr, Ptr<Closure> closurePtr);
    
    void 
    incomingData(Ptr<Data> dataPtr, Ptr<Interest> interestPtr, Ptr<Closure> closurePtr);

    void
    onVerify(const Closure::DataCallback & dataCallback, Ptr<Data> dataPtr);
    
    void
    onVerifyError(const Closure::VerifyFailCallback & failCallback, Ptr<Interest> interestPtr);
    

  private:
    Ptr<Executor> m_executor;
    Ptr<security::Keychain> m_keychain;
  };
}




#endif
