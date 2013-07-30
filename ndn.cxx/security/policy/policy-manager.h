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

#include <string>

#include "ndn.cxx/data.h"
#include "ndn.cxx/fields/name.h"

#include "ndn.cxx/security/certificate/certificate.h"

#include "policy.h"



using namespace std;


namespace ndn
{

namespace security
{
  class PolicyManager
  {
  public:
    PolicyManager();

    virtual bool setSigningPolicy(const Policy & policy) = 0;

    virtual bool setVerificationPolicy(const Policy & policy) = 0;

    virtual bool setTrustAnchor(const Certificate & certificate) = 0;

    virtual Ptr<Policy> getVerificationPolicy(const Data & data) = 0;
    
    virtual bool checkSigningPolicy(const Name & dataName, const Name & certName) = 0;
    
    virtual Name getSigningCertName(const Name & dataName) = 0;

    virtual Ptr<Data> getAnchor(const Data & data) = 0;
  private:
  };

}//security

}//ndn

#endif
