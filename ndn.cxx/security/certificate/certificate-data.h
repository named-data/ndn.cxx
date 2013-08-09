/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_DATA_H
#define NDN_CERTIFICATE_DATA_H

#include <vector>
#include <string>

#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/common.h"
#include "ndn.cxx/data.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/security/exception.h"

#include "certificate-subdescrpt.h"
#include "certificate-extension.h"
#include "publickey.h"


using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  
  class CertificateData
  {
  public:
    CertificateData(Time notBefore, Time notAfter, vector<Ptr<CertificateSubDescrypt> > & sSubjectList, Ptr<Publickey> key);
    
    CertificateData(const Blob & blob);

    CertificateData(const Data & data);

    void 
    addExtension (Ptr<CertificateExtension> extn);
    
    Ptr<Blob> 
    toDER ();

    void 
    printCertificate ();

    void 
    printSubjectInfo ();

    Time & 
    getNotBefore ()
    {
      return m_notBefore;
    }
    
    Time & 
    getNotAfter ()
    {
      return m_notAfter;
    }

    Publickey & 
    getKey ()
    {
      return *m_key;
    }

    const Publickey &
    getKey () const
    {
      return *m_key;
    }

  private:
    Ptr<Blob> 
    encodeExtn ();

    void 
    decodeExtn (const Blob & blob);

    Ptr<Blob> 
    encodeValidity ();

    void 
    decodeValidity (const Blob & blob);

    Ptr<Blob> 
    encodeSubject ();

    void 
    decodeSubject (const Blob & blob);
    
  private:
    vector<Ptr<CertificateSubDescrypt> > m_subjectList;
    Time m_notBefore;
    Time m_notAfter;
    Ptr<Publickey> m_key;
    vector<Ptr<CertificateExtension> > m_extnList;    
  };

}//security

}//ndn

#endif
