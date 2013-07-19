/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_H
#define NDN_CERTIFICATE_H

#include <vector>
#include <string>

#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/security/certificate-subdescrpt.h"
#include "ndn.cxx/security/certificate-extension.h"


using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  
  class Certificate
  {
  public:
    Certificate(string sNotBefore, string sNotAfter, vector<Ptr<CertificateSubDescrypt> > & sSubjectList, Ptr<Blob> key);

    void AddExtension(Ptr<CertificateExtension> extn);
    
    virtual Ptr<Blob> ToDER();

  private:
    virtual Ptr<Blob> ExtnToDER();

    virtual Ptr<Blob> ValidityToDER();

    virtual Ptr<Blob> SubjectToDER();
    
    virtual bool FromDER();
    
  private:
    vector<Ptr<CertificateSubDescrypt> > m_subjectList;
    ptime m_notBefore;
    ptime m_notAfter;
    Ptr<Blob> m_key;
    vector<Ptr<CertificateExtension> > m_extnList;
  };

}//security

}//ndn

#endif
