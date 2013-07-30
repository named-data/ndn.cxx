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

namespace ndn
{

namespace security
{
  Certificate::Certificate(const Data & data)
  {
    //TODO: Copy data to local;
    m_certData = Ptr<CertificateData>(new CertificateData(getContent().getContent()));
  }

  Name Certificate::getCertName()
  {
    //TODO:
    return Name();
  }

  int Certificate::getSeqNumber()
  {
    //TODO:
    return -1;
  }

  Time & Certificate::getNotBefore()
  {
    return m_certData->getNotBefore();
  }

  Time & Certificate::getNotAfter()
  {
    return m_certData->getNotAfter();
  }

  Publickey & Certificate::getPublicKeyInfo()
  {
    return m_certData->getKey();
  }

}//security

}//ndn
