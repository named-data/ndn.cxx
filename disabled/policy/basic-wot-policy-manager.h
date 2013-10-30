/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_BASIC_WOT_POLICY_MANAGER_H
#define NDN_BASIC_WOT_POLICY_MANAGER_H

#include "policy-manager.h"

namespace ndn
{

namespace security
{

  class BasicWOTPolicyManager : public PolicyManager
  {
  public:
    BasicWOTPolicyManager();

    virtual
    ~BasicWOTPolicyManager();

  protected:
    
  };

}//security

}//ndn
#endif
