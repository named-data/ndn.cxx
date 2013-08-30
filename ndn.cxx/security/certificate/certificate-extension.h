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

#include "ndn.cxx/helpers/oid.h"
#include "ndn.cxx/helpers/der/der.h"

using namespace std;

namespace ndn
{

namespace security
{
  class CertificateExtension
  {
  public:
    CertificateExtension (const string & oid, const bool & critical, const Blob & extnValue);

    CertificateExtension (const OID & oid, const bool & critical, const Blob & extnValue);

    Ptr<der::DerNode> 
    toDER();
      
  private:
    OID m_extnID;
    bool m_critical;
    Blob m_extnValue;
  };
  
}//security

}//ndn

#endif
