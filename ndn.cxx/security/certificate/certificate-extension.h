/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_EXTENSION_H
#define NDN_CERTIFICATE_EXTENSION_H

#include <vector>
#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"

#include "ndn.cxx/security/encoding/oid.h"

using namespace std;

namespace ndn
{

namespace security
{
  class CertificateExtension
  {
  public:
    CertificateExtension(string oid, bool critical, Ptr<Blob> extnValue);
    
    CertificateExtension(const Blob & blob);

    Ptr<Blob> 
    toDER();

  private:
      
  private:
    Ptr<OID> m_extnID;
    bool m_critical;
    Ptr<Blob> m_extnValue;
  };
  
}//security

}//ndn

#endif
