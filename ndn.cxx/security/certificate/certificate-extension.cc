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
    
    Ptr<vector<Ptr<Blob> > > items = decoder.DecodeSequenceDER(blob);

    m_extnID = Ptr<OID>(new OID(*(items->at(0))));
    m_critical = decoder.DecodeBoolDER(*(items->at(1)));
    m_extnValue = decoder.DecodeStringDER(*(items->at(2)));
  }

  Ptr<Blob> CertificateExtension::ToDER()
  {
    DERendec encoder;

    vector<Ptr<Blob> >items;

    items.push_back(m_extnID->ToDER());
    items.push_back(encoder.EncodeBoolDER(m_critical));
    items.push_back(encoder.EncodeStringDER(*m_extnValue));

    return encoder.EncodeSequenceDER(items);
  }

}//security

}//ndn
