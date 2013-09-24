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

namespace ndn
{

namespace security
{

  CertificateExtension::CertificateExtension(const string & oid, const bool & critical, const Blob & extnValue)
    :m_extnID(oid),
     m_critical(critical),
     m_extnValue(extnValue.buf(), extnValue.size())
  {}

  CertificateExtension::CertificateExtension(const OID & oid, const bool & critical, const Blob & extnValue)
    :m_extnID(oid),
     m_critical(critical),
     m_extnValue(extnValue.buf(), extnValue.size())
  {}

  Ptr<der::DerNode> 
  CertificateExtension::toDER()
  {
    Ptr<der::DerSequence> root = Ptr<der::DerSequence>::Create();
    
    Ptr<der::DerOid> extnID = Ptr<der::DerOid>(new der::DerOid(m_extnID));
    Ptr<der::DerBool> critical = Ptr<der::DerBool>(new der::DerBool(m_critical));
    Ptr<der::DerOctetString> extnValue = Ptr<der::DerOctetString>(new der::DerOctetString(m_extnValue));

    root->addChild(extnID);
    root->addChild(critical);
    root->addChild(extnValue);

    root->getSize();

    return root;
  }

  Ptr<Blob>
  CertificateExtension::toDERBlob()
  {
    blob_stream blobStream;
    OutputIterator & start = reinterpret_cast<OutputIterator &> (blobStream);

    toDER()->encode(start);

    return blobStream.buf ();
  }

}//security

}//ndn
