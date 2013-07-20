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
    
    m_oid = oid;
    m_value = value;
  }

  CertificateSubDescrypt::CertificateSubDescrypt(Ptr<Blob> blob)
  {
    DERendec endec;

    int offset = 0;
    Ptr<vector<Ptr<Blob> > > items = endec.DecodeSequenceDER(blob, offset);
    
    offset = 0;
    m_oid = endec.DecodeOidDER(items->at(0), offset);

    offset = 0;
    m_value = *(endec.DecodePrintableStringDER(items->at(1), offset));
  }

  Ptr<Blob> CertificateSubDescrypt::ToDER()
  {
    DERendec encoder;

    vector<Ptr<Blob> > seq;

    seq.push_back(encoder.EncodeOidDER(m_oid));
    seq.push_back(encoder.EncodePrintableStringDER(m_value));

    return encoder.EncodeSequenceDER(seq);
  }

}//ndn

}//security
