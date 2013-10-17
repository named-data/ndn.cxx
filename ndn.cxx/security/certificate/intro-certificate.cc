/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "intro-certificate.h"
#include "ndn.cxx/security/exception.h"

namespace ndn
{

namespace security
{

  IntroCertificate::IntroCertificate(const Name & keyName,
				     const Time & notBefore,
				     const Time & notAfter,
				     const Publickey & publickey,
				     const Name& nameSpace, 
				     const IntroCertificateExtension::TrustClass & trustClass, 
				     const int & trustLevel)
  {
    Name certificateName = nameSpace;
    switch(trustClass)
      {
      case IntroCertificateExtension::NORMAL_PRODUCER:
	certificateName.append("NORMAL-PRODUCER-TAG");
	break;
      case IntroCertificateExtension::INTRODUCER:
	certificateName.append("INTRODUCER-TAG");
	break;
      case IntroCertificateExtension::META_INTRODUCER:
	certificateName.append("META-INTRODUCER-TAG");
	break;
      default:
	throw SecException("Intro Certificate: Unrecognized Trust Classs!");
      }
    
    TimeInterval ti = time::NowUnixTimestamp();
    ostringstream oss;
    oss << ti.total_seconds();
    certificateName.append(keyName).append("INTRO-CERT").append(oss.str());

    setName(certificateName);
    setNotBefore(notBefore);
    setNotAfter(notAfter);
    setPublicKeyInfo(publickey);
    addSubjectDescription(CertificateSubDescrypt("2.5.4.41", keyName.toUri()));
    addExtension(IntroCertificateExtension(nameSpace, trustClass, trustLevel));
  }

  IntroCertificate::IntroCertificate(const Data & data)
    : Certificate(data)
  {
    bool introExtnExist = false;
    
    ExtensionList::iterator it = m_extnList.begin();
    for(; it != m_extnList.end(); it++)
      {
	if(it->getOID().toString() == string("1.3.6.1.5.32.1"))
	  {
	    introExtnExist = true;
	    break;
	  }
      }

    if(!introExtnExist)
      throw SecException("Intro Certificate: No Introduction Extension in Introduction Certificate!");
  }

}//security

}//ndn

