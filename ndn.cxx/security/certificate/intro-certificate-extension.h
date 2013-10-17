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
      NORMAL_PRODUCER,
      INTRODUCER,
      META_INTRODUCER,
    };

  public:
    IntroCertificateExtension (const Name& nameSpace, const TrustClass & trustClass, const int & trustLevel);

    IntroCertificateExtension (const Blob & value);

    virtual
    ~IntroCertificateExtension () {}

    inline const Name & 
    getNameSpace () const;
        
    inline const TrustClass &
    getTrustClass () const;

    inline const int &
    getTrustLevel () const;

  private:
    void
    encodeValue ();
    
    void 
    decodeValue ();

  private:
    Name m_nameSpace;
    TrustClass m_trustClass;
    int m_trustLevel;
  };

  inline const Name &
  IntroCertificateExtension::getNameSpace () const
  { return m_nameSpace; }

  inline const IntroCertificateExtension::TrustClass &
  IntroCertificateExtension::getTrustClass () const
  { return m_trustClass; }

  inline const int &
  IntroCertificateExtension::getTrustLevel () const
  { return m_trustLevel; }

}//security

}//ndn

#endif
