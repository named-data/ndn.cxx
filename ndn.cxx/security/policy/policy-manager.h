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
#include "ndn.cxx/wrapper/closure.h"

#include "policy-rule.h"
#include "validation-request.h"



using namespace std;


namespace ndn
{

namespace security
{
  class PolicyManager
  {
  public:
    PolicyManager() {}
    
    virtual
    ~PolicyManager() {}

    /**
     * @brief check if the received data packet can escape from verification
     * @param data the received data packet
     * @return true if the data does not need to be verified, otherwise false
     */
    virtual bool 
    skipVerifyAndTrust (const Data & data) = 0;

    /**
     * @brief check if PolicyManager has the verification rule for the received data
     * @param data the received data packet
     * @return true if the data must be verified, otherwise false
     */
    virtual bool
    requireVerify (const Data & data) = 0;

    /**
     * @brief check whether received data packet complies with the verification policy, and get the indication of next verification step
     * @param data the received data packet
     * @param stepCount the number of verification steps that have been done, used to track the verification progress
     * @param verifiedCallback the callback function that will be called if the received data packet has been validated
     * @param unverifiedCallback the callback function that will be called if the received data packet cannot be validated
     * @return the indication of next verification step, NULL if there is no further step
     */
    virtual Ptr<ValidationRequest>
    checkVerificationPolicy(Ptr<Data> data, 
                            const int & stepCount, 
                            const DataCallback& verifiedCallback,
                            const UnverifiedCallback& unverifiedCallback) = 0;

    
    /**
     * @brief check if the signing certificate name and data name satify the signing policy 
     * @param dataName the name of data to be signed
     * @param certificateName the name of signing certificate
     * @return true if the signing certificate can be used to sign the data, otherwise false
     */
    virtual bool 
    checkSigningPolicy(const Name & dataName, const Name & certificateName) = 0;
    
    /**
     * @brief Infer signing identity name according to policy, if the signing identity cannot be inferred, it should return empty name
     * @param dataName, the name of data to be signed
     * @return the signing identity. 
     */
    virtual Name 
    inferSigningIdentity(const Name & dataName) = 0;

    static bool
    verifySignature(const Data & data, const Publickey & publickey);

    static bool 
    verifySignature(const Blob& unsignedData, const Blob& sigBits, const Publickey& publickey);
  };

}//security

}//ndn

#endif
