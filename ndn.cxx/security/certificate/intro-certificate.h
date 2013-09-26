/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_INTRO_CERTIFICATE_H
#define NDN_INTRO_CERTIFICATE_H

#include "certificate.h"

namespace ndn
{

namespace security
{

  class IntroCertificate : public Certificate
  {
  public:
    IntroCertificate(const Name & keyName,
                     const Time & notBefore,
                     const Time & notAfter,
                     const Publickey & key,
                     const Name& nameSpace, 
                     const TrustClass & trustClass, 
                     const int & trustLevel);

    virtual
    ~IntroCertificate();
  }

}//security

}//ndn
