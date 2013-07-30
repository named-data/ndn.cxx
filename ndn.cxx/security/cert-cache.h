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

namespace ndn
{

namespace security
{

  class CertificateCache
  {
  public:
    CertificateCache();
    
    virtual bool CheckCertificate(const Name & certName) = 0;
  private:
  };
}

}//ndn

#endif
