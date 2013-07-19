/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/security/certificate-subdescrpt.h"
#include "ndn.cxx/security/der.h"

using namespace std;

namespace ndn
{

namespace security
{

  CertificateSubDescrypt::CertificateSubDescrypt(string oid, string value)
  {
    DERendec encoder;
    
    m_oid = encoder.StringToOid(oid);
    m_value = value;
  }

  Ptr<Blob> CertificateSubDescrypt::ToDER()
  {
    DERendec encoder;

    vector<Ptr<Blob> > seq;

    seq.push_back(encoder.EncodeOidDER(*m_oid));
    seq.push_back(encoder.EncodePrintableStringDER(m_value));

    return encoder.EncodeSequenceDER(seq);
  }

}//ndn

}//security
