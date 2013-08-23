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

#include "ndn.cxx/security/encoding/der.h"

namespace ndn
{

namespace security
{

  CertificateExtension::CertificateExtension(const string & oid, const bool & critical, const Blob & extnValue)
    :m_extnID(oid),
     m_critical(critical),
     m_extnValue(extnValue.buf(), extnValue.size())
  {}

  CertificateExtension::CertificateExtension(const Blob & blob)
  {
    DERendec decoder;
    
    Ptr<vector<Ptr<Blob> > > items = decoder.decodeSequenceDER(blob);

    m_extnID = OID(*(items->at(0)));
    m_critical = decoder.decodeBoolDER(*(items->at(1)));
    m_extnValue = *decoder.decodeStringDER(*(items->at(2)));
  }

  Ptr<Blob> 
  CertificateExtension::toDER()
  {
    DERendec encoder;

    vector<Ptr<Blob> >items;

    items.push_back(m_extnID.toDER());
    items.push_back(encoder.encodeBoolDER(m_critical));
    items.push_back(encoder.encodeStringDER(m_extnValue));

    return encoder.encodeSequenceDER(items);
  }

}//security

}//ndn
