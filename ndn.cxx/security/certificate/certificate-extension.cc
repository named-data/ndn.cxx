/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "certificate-extension.h"
#include "der.h"

namespace ndn
{

namespace security
{

  CertificateExtension::CertificateExtension(string oid, bool critical, Ptr<Blob> extnValue)
    :m_critical(critical),
     m_extnValue(extnValue)
  {
    m_extnID = Ptr<OID>(new OID(oid));
  }

  CertificateExtension::CertificateExtension(const Blob & blob)
  {
    DERendec decoder;
    
    Ptr<vector<Ptr<Blob> > > items = decoder.decodeSequenceDER(blob);

    m_extnID = Ptr<OID>(new OID(*(items->at(0))));
    m_critical = decoder.decodeBoolDER(*(items->at(1)));
    m_extnValue = decoder.decodeStringDER(*(items->at(2)));
  }

  Ptr<Blob> 
  CertificateExtension::toDER()
  {
    DERendec encoder;

    vector<Ptr<Blob> >items;

    items.push_back(m_extnID->toDER());
    items.push_back(encoder.encodeBoolDER(m_critical));
    items.push_back(encoder.encodeStringDER(*m_extnValue));

    return encoder.encodeSequenceDER(items);
  }

}//security

}//ndn
