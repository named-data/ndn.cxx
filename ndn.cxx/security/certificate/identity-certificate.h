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

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/security/security-common.h"
#include "certificate.h"

#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace ndn;
using namespace std;

using namespace boost::posix_time;

namespace ndn
{

namespace security
{

  class IdentityCertificate
  {
  public:
    IdentityCertificate();
    
    IdentityCertificate(Ptr<Blob> blobPtr);
    
    ~IdentityCertificate() {}
    
    virtual Ptr<Blob>ToDER();
    
    virtual Ptr<Blob>ToPEM();

    virtual Ptr<Blob>ToXML();

  private:
    virtual bool FromDER();
    
    virtual bool FromPEM();
    
    virtual bool FromXML();

  private:
    // string m_subject;
    // ptime m_notBefore;
    // ptime m_notAfter;
    // Ptr<Blob> m_keybits;
    // Vector<CertificateExtension> m_extnList;
    // Ptr<Blob> m_blobPtr;
  };

}//security

}//ndn

#endif
