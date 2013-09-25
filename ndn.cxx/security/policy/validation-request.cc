/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/security/policy/validation-request.h"

namespace ndn
{

namespace security
{
  ValidationRequest::ValidationRequest (Ptr<Interest> interest,
					const DataCallback& verifiedCallback,
					const UnverifiedCallback& unverifiedCallback,
					const int& retry)
    : m_interest(interest)
    , m_verifiedCallback(verifiedCallback)
    , m_unverifiedCallback(unverifiedCallback)
    , m_retry(retry)
  {}

}//security

}//ndn
