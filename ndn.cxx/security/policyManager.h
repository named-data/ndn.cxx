/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_POLICY_MANAGER_H
#define NDN_POLICY_MANAGER_H

namespace ndn
{

namespace security
{
  class PolicyManager
  {
  public:
    PolicyManager();

    virtual bool SetSigningPolicy(const string & policy) = 0;

    virtual bool SetVerificationPolicy(const string & policy) = 0;

    virtual bool CheckPolicy(const Name & dataName, const Name & certName) = 0;

  private:
  };

}//security

}//ndn

#endif
