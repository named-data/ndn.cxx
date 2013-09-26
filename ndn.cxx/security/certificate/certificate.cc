/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "certificate.h"

#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

#include "ndn.cxx/helpers/der/visitor/certificate-data-visitor.h"
#include "ndn.cxx/helpers/der/visitor/print-visitor.h"

#include "logging.h"

INIT_LOGGER("ndn.security.Certificate");

namespace ndn
{

namespace security
{
  Certificate::Certificate ()
    : m_notBefore(boost::date_time::pos_infin)
    , m_notAfter(boost::date_time::neg_infin)
  {}

  Certificate::Certificate (const Data & data)
  {
    //TODO: Copy data to local;
    Ptr<const signature::Sha256WithRsa> dataSig = boost::dynamic_pointer_cast<const signature::Sha256WithRsa>(data.getSignature());
    Ptr<signature::Sha256WithRsa> newSig = Ptr<signature::Sha256WithRsa>::Create();

    Ptr<SignedBlob> newSignedBlob = NULL;
    if(data.getSignedBlob() != NULL)
      newSignedBlob = Ptr<SignedBlob>(new SignedBlob(*data.getSignedBlob()));

    // _LOG_DEBUG("Start copying signature");
    
    newSig->setKeyLocator(dataSig->getKeyLocator());
    newSig->setPublisherKeyDigest(dataSig->getPublisherKeyDigest());
    newSig->setSignatureBits(dataSig->getSignatureBits());

    // _LOG_DEBUG("Finish copying signature");

    setName(data.getName());
    setSignature(newSig);
    setContent(data.getContent());
    setSignedBlob(newSignedBlob);
    
    // _LOG_DEBUG("Finish local copy: " << getContent().getContent().size());

    decode();
  }

  Certificate::~Certificate()
  {
    //TODO:
  }

  bool
  Certificate::isTooEarly()
  {
    Time now = time::Now();
    if(now < m_notBefore)
      return true;
    else
      return false;
  }

  bool 
  Certificate::isTooLate()
  {
    Time now = time::Now();
    if(now > m_notAfter)
      return true;
    else
      return false;
  }

  void
  Certificate::encode()
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
      {
        Ptr<der::DerNode> child = it->toDER();
        subjectList->addChild (child);
      }
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

    blob_stream blobStream;
    OutputIterator & start = reinterpret_cast<OutputIterator &> (blobStream);

    root->encode(start);

    Ptr<Blob> blob = blobStream.buf ();
    Content content (blob->buf(), blob->size());
    setContent (content);
  }

  void 
  Certificate::decode()
  {
    const Blob & blob = content();

    boost::iostreams::stream
      <boost::iostreams::array_source> is (blob.buf(), blob.size());

    Ptr<der::DerNode> node = der::DerNode::parse(reinterpret_cast<InputIterator &>(is));

    // der::PrintVisitor printVisitor;
    // node->accept(printVisitor, string(""));

    der::CertificateDataVisitor certDataVisitor;
    node->accept(certDataVisitor, this);
  }

  void 
  Certificate::printCertificate()
  {
    cout << "Validity:" << endl;
    cout << m_notBefore << endl;
    cout << m_notAfter << endl;

    cout << "Subject Info:" << endl;  
    vector<CertificateSubDescrypt>::iterator it = m_subjectList.begin();
    for(; it < m_subjectList.end(); it++){
      cout << it->getOidStr() << "\t" << it->getValue() << endl;
    }

    boost::iostreams::stream
      <boost::iostreams::array_source> is (m_key.getKeyBlob().buf (), m_key.getKeyBlob().size ());

    Ptr<der::DerNode> keyRoot = der::DerNode::parse(reinterpret_cast<InputIterator &> (is));

    der::PrintVisitor printVisitor;
    keyRoot->accept(printVisitor, string(""));
  }

}//security

}//ndn
