/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_CACHE_H
#define NDN_CERTIFICATE_CACHE_H

#include "ndn.cxx/common.h"

#include "ndn.cxx/security/certificate/certificate.h"

namespace ndn
{

namespace security
{

  class CertificateCache
  {
  public:
    virtual
    ~CertificateCache() {}
    
    virtual void
    insertCertificate(Ptr<Certificate> certificate) = 0;

    virtual Ptr<Certificate> 
    getCertificate(const Name & certificateName) = 0;
  };
}

}//ndn

#endif
