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

using namespace std;

namespace ndn
{

namespace security
{

  CertificateSubDescrypt::CertificateSubDescrypt (string oid, string value)
    :m_oid(oid),
     m_value(value)
  {}

  CertificateSubDescrypt::CertificateSubDescrypt (OID oid, string value)
    :m_oid(oid),
     m_value(value)
  {}

  Ptr<der::DerNode> 
  CertificateSubDescrypt::toDER()
  {
    Ptr<der::DerSequence> root = Ptr<der::DerSequence>::Create();
    
    Ptr<der::DerOid> oid = Ptr<der::DerOid>(new der::DerOid(m_oid));
    Ptr<der::DerPrintableString> value = Ptr<der::DerPrintableString>(new der::DerPrintableString(m_value));

    root->addChild(oid);
    root->addChild(value);

    return root;
  }

}//ndn

}//security
