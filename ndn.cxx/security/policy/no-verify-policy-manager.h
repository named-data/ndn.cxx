/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_NO_VERIFY_POLICY_MANAGER_H
#define NDN_NO_VERIFY_POLICY_MANAGER_H

#include "policy-manager.h"

namespace ndn
{

namespace security
{

  class NoVerifyPolicyManager : public PolicyManager
  {
  public:
    NoVerifyPolicyManager();
    
    virtual 
    ~NoVerifyPolicyManager();

     /**
     * @brief check if the received data packet can escape from verification
     * @param data the received data packet
     * @return true if the data does not need to be verified, otherwise false
     */
    inline virtual bool 
    skipVerify (const Data & data);
    

    /**
     * @brief check if PolicyManager has the verification rule for the received data
     * @param data the received data packet
     * @return true if the data must be verified, otherwise false
     */
    inline virtual bool
    requireVerify (const Data & data);

    /**
     * @brief check whether received data packet complies with the verification policy, and get the indication of next verification step
     * @param data the received data packet
     * @param stepCount the number of verification steps that have been done, used to track the verification progress
     * @param verifiedCallback the callback function that will be called if the received data packet has been validated
     * @param unverifiedCallback the callback function that will be called if the received data packet cannot be validated
     * @return the indication of next verification step, NULL if there is no further step
     */
    inline virtual Ptr<ValidationRequest>
    checkVerificationPolicy(Ptr<Data> data, 
                            const int & stepCount, 
                            const DataCallback& verifiedCallback,
                            const UnverifiedCallback& unverifiedCallback);

    
    /**
     * @brief check if the signing certificate name and data name satify the signing policy 
     * @param dataName the name of data to be signed
     * @param certificateName the name of signing certificate
     * @return true if the signing certificate can be used to sign the data, otherwise false
     */
    inline virtual bool 
    checkSigningPolicy(const Name & dataName, const Name & certificateName);
    
    /**
     * @brief Infer signing identity name according to policy, if the signing identity cannot be inferred, it should return empty name
     * @param dataName, the name of data to be signed
     * @return the signing identity. 
     */
    inline virtual Name 
    inferSigningIdentity(const Name & dataName);
  };

  inline bool 
  NoVerifyPolicyManager::skipVerifyAndTrust (const Data & data)
  { return true; }

  inline bool
  NoVerifyPolicyManager::requireVerify (const Data & data)
  { return false; }
    

  inline Ptr<ValidationRequest>
  NoVerifyPolicyManager::checkVerificationPolicy(Ptr<Data> data, 
                                                 const int & stepCount, 
                                                 const DataCallback& verifiedCallback,
                                                 const UnverifiedCallback& unverifiedCallback)
  { 
    verifiedCallback(data); 
    return NULL;
  }

  inline bool 
  NoVerifyPolicyManager::checkSigningPolicy(const Name & dataName, const Name & certificateName)
  { return true; }

  inline Name 
  NoVerifyPolicyManager::inferSigningIdentity(const Name & dataName)
  { return Name(); }

}//security

}//ndn

#endif
