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
#include "certificate-data.h"

#include "logging.h"

INIT_LOGGER("ndn.security.CertificateData");

using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  CertificateData::CertificateData(Time notBefore, Time notAfter, vector<Ptr<CertificateSubDescrypt> > & sSubjectList, Ptr<Publickey> key)
  {
    m_notBefore = notBefore;
    m_notAfter  = notAfter;
    m_key = key;
    m_subjectList = sSubjectList;
  }

  CertificateData::CertificateData(const Blob & blob)
  {
    DERendec decoder;

    Ptr<vector<Ptr<Blob> > > items = decoder.decodeSequenceDER(blob);

    decodeValidity(*items->at(0));

    decodeSubject(*items->at(1));

    m_key = Ptr<Publickey>(new Publickey(*items->at(2), false));

    if(4 == items->size())
      decodeExtn(*items->at(3));
  }

  CertificateData::CertificateData(const Data & data)
  {
    //TODO
  }


  void 
  CertificateData::addExtension(Ptr<CertificateExtension> extn)
  {
    m_extnList.push_back(extn);
  }

  Ptr<Blob> 
  CertificateData::toDER()
  {
    vector<Ptr<Blob> > certSeq;

    certSeq.push_back(encodeValidity());
    certSeq.push_back(encodeSubject());
    certSeq.push_back(m_key->getKeyBlob());
    if(0 != m_extnList.size())
      certSeq.push_back(encodeExtn());
    
    DERendec encoder;
    
    return encoder.encodeSequenceDER(certSeq);
  }

  Ptr<Blob> 
  CertificateData::encodeSubject()
  {
    vector<Ptr<Blob> > subjectSeq;

    vector<Ptr<CertificateSubDescrypt> >::iterator it = m_subjectList.begin();
    for(; it < m_subjectList.end(); it++){
      subjectSeq.push_back((*it)->toDER());
    }

    DERendec encoder;

    if(0 == m_subjectList.size())
      return NULL;
    else
      return encoder.encodeSequenceDER(subjectSeq);
  }

  void 
  CertificateData::decodeSubject(const Blob & blob)
  {
    DERendec endec;

    int offset = 0;

    Ptr<vector<Ptr<Blob> > > items = endec.decodeSequenceDER(blob);

    vector<Ptr<Blob> >::iterator it = items->begin();
    
    for(; it < items->end(); it++){
      m_subjectList.push_back(Ptr<CertificateSubDescrypt>(new CertificateSubDescrypt(**it)));
    }
  }

  Ptr<Blob> 
  CertificateData::encodeValidity()
  {
    vector<Ptr<Blob> > validSeq;
    
    DERendec encoder;

    validSeq.push_back(encoder.encodeGTimeDER(m_notBefore));
    validSeq.push_back(encoder.encodeGTimeDER(m_notAfter));

    return encoder.encodeSequenceDER(validSeq);
  }

  void 
  CertificateData::decodeValidity(const Blob & blob)
  {
    DERendec decoder;

    Ptr<vector<Ptr<Blob> > > items = decoder.decodeSequenceDER(blob);
    m_notBefore = decoder.decodeGTimeDER(*items->at(0));
    m_notAfter  = decoder.decodeGTimeDER(*items->at(1));
  }

  Ptr<Blob> 
  CertificateData::encodeExtn()
  {
    vector<Ptr<Blob> > extnSeq;

    vector<Ptr<CertificateExtension> >::iterator it = m_extnList.begin();
    for(; it < m_extnList.end(); it++){
      extnSeq.push_back((*it)->toDER());
    }

    DERendec encoder;

    if(0 == m_extnList.size())
      return NULL;
    else
      return encoder.encodeSequenceDER(extnSeq);
  }

  void 
  CertificateData::decodeExtn(const Blob & blob)
  {
    DERendec endec;

    int offset = 0;

    Ptr<vector<Ptr<Blob> > > items = endec.decodeSequenceDER(blob);

    vector<Ptr<Blob> >::iterator it = items->begin();
    
    for(; it < items->end(); it++){
      m_extnList.push_back(Ptr<CertificateExtension>(new CertificateExtension(**it)));
    }
  }

  void 
  CertificateData::printSubjectInfo()
  {
    cout << "Subject Info:" << endl;
      
    vector<Ptr<CertificateSubDescrypt> >::iterator it = m_subjectList.begin();
    for(; it < m_subjectList.end(); it++){
      cout << (*it)->getOidStr() << "\t" << (*it)->getValue() << endl;
    }
  }

  void 
  CertificateData::printCertificate()
  {
    DERendec decoder;

    printSubjectInfo();
    cout << "Validity:" << endl;
    cout << getNotBefore() << "\t" << getNotAfter() << endl;
    decoder.printDecoded(*m_key->getKeyBlob(), "", 0);
  }

}//security

}//ndn
