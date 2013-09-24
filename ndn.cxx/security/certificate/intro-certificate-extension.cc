/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "intro-certificate-extension.h"

#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/helpers/der/der.h"
#include "ndn.cxx/helpers/der/visitor/simple-visitor.h"

namespace ndn
{

namespace security
{
  IntroCertificateExtension::IntroCertificateExtension(const Name & nameSpace, const TrustClass & trustClass, const int & trustLevel)
    : CertificateExtension("1.3.6.1.5.32.1", true, Blob())
    , m_nameSpace(nameSpace)
    , m_trustClass(trustClass)
  {
    if(trustLevel > 100 || trustLevel < 0)
      throw SecException("trust level is out of range!");
    m_trustLevel = trustLevel;

    encodeValue();
  }

  IntroCertificateExtension::IntroCertificateExtension(const Blob & value)
    : CertificateExtension("1.3.6.1.5.32.1", true, value)
  {
    decodeValue();
  }
  
  void
  IntroCertificateExtension::encodeValue()
  {
    Ptr<der::DerSequence> root = Ptr<der::DerSequence>::Create();
    
    Ptr<der::DerOctetString> nameSpace = Ptr<der::DerOctetString>(new der::DerOctetString(m_nameSpace.toUri()));

    Blob trustClassBlob;
    switch(m_trustClass)
      {
      case PRODUCER:
	trustClassBlob.push_back(0);
	break;
      case INTRODUCER:
	trustClassBlob.push_back(1);
	break;
      case META_INTRODUCER:
	trustClassBlob.push_back(2);
	break;
      }
    Ptr<der::DerInteger> trustClass = Ptr<der::DerInteger>(new der::DerInteger(trustClassBlob));

    Blob trustLevelBlob;
    trustLevelBlob.push_back(m_trustLevel);
    Ptr<der::DerInteger> trustLevel = Ptr<der::DerInteger>(new der::DerInteger(trustLevelBlob));

    root->addChild(nameSpace);
    root->addChild(trustClass);
    root->addChild(trustLevel);

    blob_stream blobStream;
    OutputIterator & start = reinterpret_cast<OutputIterator &> (blobStream);

    root->encode(start);
    Ptr<Blob> encodedBlob = blobStream.buf ();
    m_extnValue.insert(m_extnValue.end(), encodedBlob->begin(), encodedBlob->end());
  }

  void 
  IntroCertificateExtension::decodeValue()
  {
    boost::iostreams::stream
      <boost::iostreams::array_source> is (m_extnValue.buf(), m_extnValue.size());

    Ptr<der::DerSequence> root = DynamicCast<der::DerSequence>(der::DerNode::parse(reinterpret_cast<InputIterator &>(is)));

    const der::DerNodePtrList & children = root->getChildren();

    if(children.size() != 3)
      throw SecException ("IntroCertificateExtension vale is mal-formatted!");
    
    der::SimpleVisitor simpleVisitor;

    m_nameSpace = Name(boost::any_cast<string>(children[0]->accept(simpleVisitor)));

    const Blob& trustClassBlob = boost::any_cast<const Blob &>(children[1]->accept(simpleVisitor));
    if(trustClassBlob.size() != 1 || 0 > trustClassBlob[0] || 2 < trustClassBlob[0])
      throw SecException ("Wrong value of trustClass!");
    switch(trustClassBlob[0])
      {
      case 0:
	m_trustClass = PRODUCER;
	break;
      case 1:
	m_trustClass = INTRODUCER;
	break;
      case 2:
	m_trustClass = META_INTRODUCER;
	break;
      }
    
    const Blob& trustLevelBlob = boost::any_cast<const Blob &>(children[2]->accept(simpleVisitor));
    if(trustLevelBlob.size() != 1 || 0 > trustLevelBlob[0] || 100 < trustLevelBlob[0])
      throw SecException ("Wrong value of trustLevel!");
    m_trustLevel = trustLevelBlob[0];
  }

}//security

}//ndn
