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

    IdentityCertificate(const IdentityCertificate& identityCertificate);
    
    IdentityCertificate(const Data& data);

    virtual
    ~IdentityCertificate()
    {}

    Data &
    setName (const Name& name);

    inline Name
    getPublicKeyName () const
    { return m_publicKeyName; }


    static bool
    isIdentityCertificate(const Certificate& certificate);

  private:
    static bool
    isCorrectName(const Name& name);
    
    void
    setPublicKeyName();
    
  protected:
    Name m_publicKeyName;

    
  };

}//security

}//ndn

#endif
