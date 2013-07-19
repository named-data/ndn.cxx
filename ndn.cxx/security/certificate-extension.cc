/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "ndn.cxx/security/certificate-extension.h"

namespace ndn
{

namespace security
{

  CertificateExtension::CertificateExtension(string oid, bool critical, Ptr<Blob> extnValue)
  {
    
  }

  CertificateExtension::CertificateExtension(Ptr<Blob> blob)
  {
  }

  Ptr<Blob> CertificateExtension::ToDER()
  {
    return Ptr<Blob>::Create();
  }

}//security

}//ndn
