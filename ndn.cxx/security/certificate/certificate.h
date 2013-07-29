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
#include "ndn.cxx/data.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/security/exception.h"

#include "certificate-subdescrpt.h"
#include "certificate-extension.h"


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
    
    Certificate(const Blob & blob);

    Certificate(const Data & data);

    void AddExtension(Ptr<CertificateExtension> extn);
    
    virtual Ptr<Blob> ToDER();

    void PrintCertificate();

    void PrintSubjectInfo();

    string GetNotBefore(){return m_notBefore;}
    
    string GetNotAfter(){return m_notAfter;}

    Ptr<Blob> GetKey(){return m_key;}

  private:
    virtual Ptr<Blob> ExtnToDER();

    virtual void DERToExtn (const Blob & blob);

    virtual Ptr<Blob> ValidityToDER();

    virtual void DERToValidity(const Blob & blob);

    virtual Ptr<Blob> SubjectToDER();

    virtual void DERToSubject(const Blob & blob);
    
  private:
    vector<Ptr<CertificateSubDescrypt> > m_subjectList;
    string m_notBefore;
    string m_notAfter;
    Ptr<Blob> m_key;
    vector<Ptr<CertificateExtension> > m_extnList;    
  };

}//security

}//ndn

#endif
