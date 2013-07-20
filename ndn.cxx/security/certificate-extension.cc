/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "ndn.cxx/security/certificate-extension.h"
#include "ndn.cxx/security/der.h"

namespace ndn
{

namespace security
{

  CertificateExtension::CertificateExtension(string oid, bool critical, Ptr<Blob> extnValue)
    :m_extnID(oid), 
     m_critical(critical),
     m_extnValue(extnValue)
  {}

  CertificateExtension::CertificateExtension(Ptr<Blob> blob)
  {
    DERendec decoder;

    int offset = 0;
    
    Ptr<vector<Ptr<Blob> > > items = decoder.DecodeSequenceDER(blob, offset);

    offset = 0;
    m_extnID = decoder.DecodeOidDER(items->at(0), offset);

    offset = 0;
    m_critical = decoder.DecodeBoolDER(items->at(1), offset);
    
    offset = 0;
    m_extnValue = decoder.DecodeStringDER(items->at(2), offset);
  }

  Ptr<Blob> CertificateExtension::ToDER()
  {
    DERendec encoder;

    vector<Ptr<Blob> >items;

    items.push_back(encoder.EncodeOidDER(m_extnID));
    items.push_back(encoder.EncodeBoolDER(m_critical));
    items.push_back(encoder.EncodeStringDER(m_extnValue));

    return encoder.EncodeSequenceDER(items);
  }

}//security

}//ndn
