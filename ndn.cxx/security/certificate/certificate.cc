/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "der.h"
#include "certificate.h"


using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  Certificate::Certificate(string sNotBefore, string sNotAfter, vector<Ptr<CertificateSubDescrypt> > & sSubjectList, Ptr<Blob> key)
  {
    m_notBefore = sNotBefore;
    m_notAfter  = sNotAfter;
    m_key = key;
    m_subjectList = sSubjectList;
  }

  Certificate::Certificate(const Blob & blob)
  {
    DERendec decoder;

    Ptr<vector<Ptr<Blob> > > items = decoder.DecodeSequenceDER(blob);

    DERToValidity(*items->at(0));

    DERToSubject(*items->at(1));

    m_key = items->at(2);

    if(4 == items->size())
      DERToExtn(*items->at(3));
  }

  Certificate::Certificate(const Data & data)
  {
    //TODO
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

  void Certificate::DERToSubject(const Blob & blob)
  {
    DERendec endec;

    int offset = 0;

    Ptr<vector<Ptr<Blob> > > items = endec.DecodeSequenceDER(blob);

    vector<Ptr<Blob> >::iterator it = items->begin();
    
    for(; it < items->end(); it++){
      m_subjectList.push_back(Ptr<CertificateSubDescrypt>(new CertificateSubDescrypt(**it)));
    }
  }

  Ptr<Blob> Certificate::ValidityToDER()
  {
    vector<Ptr<Blob> > validSeq;
    
    DERendec encoder;

    validSeq.push_back(encoder.EncodeGTimeDER(m_notBefore));
    validSeq.push_back(encoder.EncodeGTimeDER(m_notAfter));

    return encoder.EncodeSequenceDER(validSeq);
  }

  void Certificate::DERToValidity(const Blob & blob)
  {
    DERendec decoder;

    Ptr<vector<Ptr<Blob> > > items = decoder.DecodeSequenceDER(blob);
    m_notBefore = decoder.DecodeGTimeDER(*items->at(0));
    m_notAfter  = decoder.DecodeGTimeDER(*items->at(1));
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

  void Certificate::DERToExtn(const Blob & blob)
  {
    DERendec endec;

    int offset = 0;

    Ptr<vector<Ptr<Blob> > > items = endec.DecodeSequenceDER(blob);

    vector<Ptr<Blob> >::iterator it = items->begin();
    
    for(; it < items->end(); it++){
      m_extnList.push_back(Ptr<CertificateExtension>(new CertificateExtension(**it)));
    }
  }

  void Certificate::PrintSubjectInfo()
  {
    cout << "Subject Info:" << endl;
      
    vector<Ptr<CertificateSubDescrypt> >::iterator it = m_subjectList.begin();
    for(; it < m_subjectList.end(); it++){
      cout << (*it)->GetOid() << "\t" << (*it)->GetValue() << endl;
    }
  }

  void Certificate::PrintCertificate()
  {
    DERendec decoder;

    PrintSubjectInfo();
    cout << "Validity:" << endl;
    cout << GetNotBefore() << "\t" << GetNotAfter() << endl;
    decoder.PrintDecoded(*m_key, "", 0);
  }

}//security

}//ndn
