/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_SUB_DESCRYPT_H
#define NDN_CERTIFICATE_SUB_DESCRYPT_H

#include <vector>

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"

#include "ndn.cxx/helpers/oid.h"

using namespace std;

namespace ndn
{

namespace security
{
  class CertificateSubDescrypt
  {
  public:
    CertificateSubDescrypt (string oid, string value);

    CertificateSubDescrypt (OID oid, string value);
    
    CertificateSubDescrypt (const Blob & blob);

    Ptr<Blob> 
    toDER ();

    string
    getOidStr ()
    {
      return m_oid.toString();
    }

    const string &
    getValue () const
    {
      return m_value;
    }
    
  private:
    OID m_oid;
    string m_value;
  };

}//security

}//ndn

#endif
