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
#include "ndn.cxx/helpers/der/der.h"

#include "certificate-subdescrpt.h"
#include "certificate-extension.h"
#include "publickey.h"


using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  typedef vector<CertificateSubDescrypt> SubDescryptList;
  typedef vector<CertificateExtension> ExtensionList;
  
  class CertificateData
  {
  public:
    CertificateData () {}

    CertificateData (Time m_notBefore, Time m_notAfter, const Publickey & publickey);

    static Ptr<CertificateData>
    fromDER(Ptr<Blob> blob);

    static Ptr<CertificateData>
    fromDER(const Blob & blob);

    Ptr<Blob> 
    toDERBlob ();

    Ptr<der::DerNode>
    toDER ();

    void 
    addSubjectDescription (const CertificateSubDescrypt & descrypt) 
    { m_subjectList.push_back(descrypt); }

    void 
    addExtension (const CertificateExtension & extn) 
    { m_extnList.push_back(extn); }

    void
    setNotBefore (const Time & notBefore)
    { m_notBefore = notBefore; }

    Time & 
    getNotBefore ()
    { return m_notBefore; } 

    void
    setNotAfter (const Time & notAfter)
    { m_notAfter = notAfter; }
    
    Time & 
    getNotAfter ()
    { return m_notAfter; }

    void
    setKey (const Publickey & key)
    { m_key = key; }

    Publickey & 
    getKey () 
    { return m_key; }

    const Publickey &
    getKey () const
    { return m_key; }

    void 
    printCertificate ();

  private:
    SubDescryptList m_subjectList;
    Time m_notBefore;
    Time m_notAfter;
    Publickey m_key;
    ExtensionList m_extnList;    
  };

}//security

}//ndn

#endif
