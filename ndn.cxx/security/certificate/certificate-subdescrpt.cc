/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "certificate-subdescrpt.h"
#include "der.h"

using namespace std;

namespace ndn
{

namespace security
{

  CertificateSubDescrypt::CertificateSubDescrypt(string oid, string value)
  {
    DERendec encoder;
    
    m_oid = Ptr<OID>(new OID(oid));
    m_value = value;
  }

  CertificateSubDescrypt::CertificateSubDescrypt(const Blob & blob)
  {
    DERendec endec;

    Ptr<vector<Ptr<Blob> > > items = endec.DecodeSequenceDER(blob);
    
    m_oid = Ptr<OID>(new OID(*(items->at(0))));
    m_value = *(endec.DecodePrintableStringDER(*(items->at(1))));
  }

  Ptr<Blob> CertificateSubDescrypt::ToDER()
  {
    DERendec encoder;

    vector<Ptr<Blob> > seq;

    seq.push_back(m_oid->ToDER());
    seq.push_back(encoder.EncodePrintableStringDER(m_value));

    return encoder.EncodeSequenceDER(seq);
  }

}//ndn

}//security
