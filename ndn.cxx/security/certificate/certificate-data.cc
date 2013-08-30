/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "certificate-data.h"


#include "logging.h"

INIT_LOGGER("ndn.security.CertificateData");

using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  CertificateData::CertificateData(Time notBefore, Time notAfter, const Publickey & publickey)
    :m_notBefore(notBefore),
     m_notAfter(notAfter),
     m_key(publickey)
  {}

  Ptr<CertificateData>
  CertificateData::fromDER(const Blob & blob)
  {
    boost::iostreams::stream
      <boost::iostreams::array_source> is (blob.buf(), blob.size());

    Ptr<der::DerNode> node = der::DerNode::parse(reinterpret_cast<InputIterator &>(is));

    der::CertificateDataVisitor certDataVisitor;
    Ptr<CertificateData> certData = Ptr<CertificateData>::Create();
    node->accept(certDataVisitor, GetPointer(certData));

    return certData;
  }

  Ptr<CertificateData>
  CertificateData::fromDER(Ptr<Blob> blob)
  {
    return fromDER(*blob);
  }

  Ptr<Blob>
  CertificateData::toDERBlob ()
  {
    blob_stream blobStream;

    OutputIterator & start = reinterpret_cast<OutputIterator &> (blobStream);

    toDER()->encode(start);

    return blobStream.buf ();
  }

  Ptr<der::DerNode> 
  CertificateData::toDER ()
  {
    Ptr<der::DerSequence> root = Ptr<der::DerSequence>::Create();
    
    Ptr<der::DerSequence> validity = Ptr<der::DerSequence>::Create();
    Ptr<der::DerGtime> notBefore = Ptr<der::DerGtime>(new der::DerGtime(m_notBefore));
    Ptr<der::DerGtime> notAfter = Ptr<der::DerGtime>(new der::DerGtime(m_notAfter));
    validity->addChild (notBefore);
    validity->addChild (notAfter);
    root->addChild (validity);

    Ptr<der::DerSequence> subjectList = Ptr<der::DerSequence>::Create();
    SubDescryptList::iterator it = m_subjectList.begin();
    for(; it != m_subjectList.end(); it++)
      subjectList->addChild (it->toDER());
    root->addChild (subjectList);

    root->addChild (m_key.toDER());

    if(!m_extnList.empty())
      {
        Ptr<der::DerSequence> extnList = Ptr<der::DerSequence>::Create();
        ExtensionList::iterator it = m_extnList.begin();
        for(; it != m_extnList.end(); it++)
          extnList->addChild (it->toDER());
        root->addChild (extnList);
      }

    return root;
  }

}//security

}//ndn
