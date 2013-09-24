/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_INTRO_CERTIFICATE_EXTENSION_H
#define NDN_INTRO_CERTIFICATE_EXTENSION_H

#include "certificate-extension.h"
#include "ndn.cxx/fields/name.h"


namespace ndn
{

namespace security
{
  class IntroCertificateExtension : public CertificateExtension
  {
  public:
    enum TrustClass {
      PRODUCER,
      INTRODUCER,
      META_INTRODUCER,
    };

  public:
    IntroCertificateExtension(const Name& nameSpace, const TrustClass & trustClass, const int & trustLevel);

    IntroCertificateExtension(const Blob & value);

    virtual
    ~IntroCertificateExtension() {}

  private:
    void
    encodeValue();
    
    void 
    decodeValue();

  private:
    Name m_namespace;
    TrustClass m_trustClass;
    int m_trustLevel;
  };

}//security

}//ndn

#endif
