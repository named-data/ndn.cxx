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

    virtual void 
    setSigningPolicy(const string & policy) = 0;

    virtual void 
    setSigningInference(const string & inference) = 0;

    virtual void 
    setVerificationPolicy(const string & policy) = 0;

    virtual void 
    setTrustAnchor(const Certificate & certificate) = 0;

    virtual bool 
    skipVerify (const Data & data) = 0;

    virtual bool
    requireVerify (const Data & data) = 0;

    virtual Ptr<const Certificate>
    getTrustAnchor(const Name & anchorName) = 0;

    virtual bool 
    checkVerificationPolicy(const Data & data) = 0;
    
    virtual bool 
    checkSigningPolicy(const Name & dataName, const Name & certName) = 0;
    
    virtual Name 
    inferSigningCert(const Name & dataName) = 0;


  private:
  };

}//security

}//ndn

#endif
