/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_IDENTITY_CERTIFICATE_H
#define NDN_IDENTITY_CERTIFICATE_H

#include "certificate.h"

namespace ndn
{

namespace security
{

  class IdentityCertificate : public Certificate
  {
  public:
    IdentityCertificate();
    
    IdentityCertificate(const Data& data);

    virtual
    ~IdentityCertificate()
    {}

    Data &
    setName (const Name& name);

    virtual Name 
    getPublicKeyName ();

    static bool
    isIdentityCertificate(const Data& data);

  private:
    static bool
    isCorrectName(const Name& name);
    
  };

}//security

}//ndn

#endif
