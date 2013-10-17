/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_VALIDATION_REQUEST_H
#define NDN_VALIDATION_REQUEST_H

#include "ndn.cxx/wrapper/closure.h"

namespace ndn
{

namespace security
{
  /**
   * @brief Request which can direct Keychain to process validation
   */
  class ValidationRequest
  {
  public:
    ValidationRequest (Ptr<Interest> interest,
                       const DataCallback& verifiedCallback,
                       const UnverifiedCallback& unverifiedCallback,
                       const int& retry,
                       const int& stepCount);
    
    virtual
    ~ValidationRequest () {}

  public:
    Ptr<Interest> m_interest;    // interest packet to fetch the requested data
    DataCallback m_verifiedCallback; // callback function if requested certificate has been validated
    UnverifiedCallback m_unverifiedCallback; //callback function if requested certificate cannot be validated
    int m_retry; // number of retrials when interest timeout
    int m_stepCount;
  };

}//security

}//ndn

#endif
