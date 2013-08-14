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

#include "logging.h"

INIT_LOGGER("ndn.security.Certificate");

namespace ndn
{

namespace security
{
  Certificate::Certificate(const Data & data)
  {
    //TODO: Copy data to local;
    Ptr<const signature::Sha256WithRsa> dataSig = boost::dynamic_pointer_cast<const signature::Sha256WithRsa>(data.getSignature());
    Ptr<signature::Sha256WithRsa> newSig = Ptr<signature::Sha256WithRsa>::Create();

    // _LOG_DEBUG("Start copying signature");
    
    newSig->setKeyLocator(dataSig->getKeyLocator());
    newSig->setPublisherKeyDigest(dataSig->getPublisherKeyDigest());
    newSig->setSignatureBits(dataSig->getSignatureBits());

    // _LOG_DEBUG("Finish copying signature");

    setName(data.getName());
    setSignature(newSig);
    setContent(data.getContent());
    
    // _LOG_DEBUG("Finish local copy: " << getContent().getContent().size());

    m_certData = Ptr<CertificateData>(new CertificateData(getContent().getContent()));
  }

  Certificate::~Certificate()
  {
    //TODO:
  }

  Name 
  Certificate::getCertName()
  {
    //TODO:
    return Name();
  }

  int 
  Certificate::getSeqNumber()
  {
    //TODO:
    return -1;
  }

  Time & 
  Certificate::getNotBefore()
  {
    return m_certData->getNotBefore();
  }

  const Time & 
  Certificate::getNotBefore() const
  {
    return m_certData->getNotBefore();
  }

  Time & 
  Certificate::getNotAfter()
  {
    return m_certData->getNotAfter();
  }
  
  const Time & 
  Certificate::getNotAfter() const
  {
    return m_certData->getNotAfter();
  }

  Publickey & 
  Certificate::getPublicKeyInfo()
  {
    return m_certData->getKey();
  }

  const Publickey & 
  Certificate::getPublicKeyInfo() const
  {
    return m_certData->getKey();
  }

}//security

}//ndn
