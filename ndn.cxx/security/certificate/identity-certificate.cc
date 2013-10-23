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

#include "logging.h"

INIT_LOGGER("IdentityCertificate");

namespace ndn
{

namespace security
{

  IdentityCertificate::IdentityCertificate()
    : Certificate()
  {}

  IdentityCertificate::IdentityCertificate(const IdentityCertificate& identityCertificate)
    : Certificate(identityCertificate)
    , m_publicKeyName(identityCertificate.m_publicKeyName)
  {}
    
  IdentityCertificate::IdentityCertificate(const Data& data)
    : Certificate(data)
  {
    if(!isCorrectName(data.getName()))
      throw SecException("Wrong Identity Certificate Name!");
    
    setPublicKeyName();
  }

  bool
  IdentityCertificate::isCorrectName(const Name& name)
  {
    int i = name.size() - 1;
    
    string idString("ID-CERT");
    for (; i >= 0; i--)
      if(name.get(i).toUri() == idString)
	break;

    if (i < 0)
      return false;

    int keyIdx = 0;
    string keyString("KEY");
    for (; keyIdx < name.size(); keyIdx++)
      if(name.get(keyIdx).toUri() == keyString)
        break;

    if (keyIdx >= name.size())
      return false;

    return true;
  }

  Data &
  IdentityCertificate::setName (const Name& name)
  {
    if(!isCorrectName(name))
      throw SecException("Wrong Identity Certificate Name!");
    
    Data::setName(name);
    setPublicKeyName();
    return *this;
  }

  void
  IdentityCertificate::setPublicKeyName()
  {
    const Name & certificateName = getName ();

    int i = certificateName.size() - 1;
    string idString("ID-CERT");
    for (; i >= 0; i--)
      if(certificateName.get(i).toUri() == idString)
	break; 
    
    Name tmpName = certificateName.getSubName(0, i);    
    string keyString("KEY");
    for (i = 0; i < tmpName.size(); i++)
      if(tmpName.get(i).toUri() == keyString)
          break;
    m_publicKeyName = tmpName.getSubName(0, i).append(tmpName.getSubName(i+1, tmpName.size() - i - 1));
  }

  bool
  IdentityCertificate::isIdentityCertificate(const Certificate& certificate)
  { return (isCorrectName(certificate.getName()) ? true : false); }

}//security

}//ndn
