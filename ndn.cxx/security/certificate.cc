/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/security/der.h"
#include "ndn.cxx/security/certificate.h"


using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  Certificate::Certificate(string sNotBefore, string sNotAfter, vector<Ptr<CertificateSubDescrypt> > & sSubjectList, Ptr<Blob> key)
  {
    m_notBefore = from_iso_string(sNotBefore.substr(0, 8) + "T" + sNotBefore.substr(8, 6));
    m_notAfter  = from_iso_string(sNotAfter.substr(0, 8) + "T" + sNotAfter.substr(8, 6));
    m_key = key;
    m_subjectList = sSubjectList;
  }

  void Certificate::AddExtension(Ptr<CertificateExtension> extn)
  {
    m_extnList.push_back(extn);
  }

  Ptr<Blob> Certificate::ToDER()
  {
    vector<Ptr<Blob> > certSeq;

    certSeq.push_back(ValidityToDER());
    certSeq.push_back(SubjectToDER());
    certSeq.push_back(m_key);
    if(0 != m_extnList.size())
      certSeq.push_back(ExtnToDER());
    
    DERendec encoder;
    
    return encoder.EncodeSequenceDER(certSeq);
  }

  Ptr<Blob> Certificate::SubjectToDER()
  {
    vector<Ptr<Blob> > subjectSeq;

    vector<Ptr<CertificateSubDescrypt> >::iterator it = m_subjectList.begin();
    for(; it < m_subjectList.end(); it++){
      subjectSeq.push_back((*it)->ToDER());
    }

    DERendec encoder;

    if(0 == m_subjectList.size())
      return NULL;
    else
      return encoder.EncodeSequenceDER(subjectSeq);
  }

  Ptr<Blob> Certificate::ValidityToDER()
  {
    vector<Ptr<Blob> > validSeq;
    
    DERendec encoder;

    validSeq.push_back(encoder.EncodeGTimeDER(m_notBefore));
    validSeq.push_back(encoder.EncodeGTimeDER(m_notAfter));

    return encoder.EncodeSequenceDER(validSeq);
  }

  Ptr<Blob> Certificate::ExtnToDER()
  {
    vector<Ptr<Blob> > extnSeq;

    vector<Ptr<CertificateExtension> >::iterator it = m_extnList.begin();
    for(; it < m_extnList.end(); it++){
      extnSeq.push_back((*it)->ToDER());
    }

    DERendec encoder;

    if(0 == m_extnList.size())
      return NULL;
    else
      return encoder.EncodeSequenceDER(extnSeq);
  }

  bool Certificate::FromDER(){
    return false;
  }

}//security

}//ndn
