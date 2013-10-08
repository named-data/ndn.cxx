/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "identity-certificate.h"
#include "ndn.cxx/security/exception.h"

namespace ndn
{

namespace security
{

  IdentityCertificate::IdentityCertificate()
    : Certificate()
  {}
    
  IdentityCertificate::IdentityCertificate(const Data& data)
    : Certificate(data)
  {
    if(!isCorrectName(data.getName()))
      throw SecException("Wrong Identity Certificate Name!");
  }

  bool
  IdentityCertificate::isCorrectName(const Name& name)
  {
    int i = name.size() - 1;
    
    for (; i >= 0; i--)
      if(name.get(i).toUri() == string("ID-CERT"))
	break;

    if (i < 0)
      return false;
    
    return true;
  }

  Data &
  IdentityCertificate::setName (const Name& name)
  {
    if(!isCorrectName(name))
      throw SecException("Wrong Identity Certificate Name!");
    
    Data::setName(name);
    return *this;
  }

  Name
  IdentityCertificate::getPublicKeyName() const
  {
    const Name & certificateName = getName ();
    int i = certificateName.size() - 1;

    for (; i >= 0; i--)
      if(certificateName.get(i).toUri() == string("ID-CERT"))
	break; 
    
    return certificateName.getSubName(0, i);
  }

  bool
  IdentityCertificate::isIdentityCertificate(const Certificate& certificate)
  { return (isCorrectName(certificate.getName()) ? true : false); }

}//security

}//ndn
