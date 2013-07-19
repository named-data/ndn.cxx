/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <tinyxml.h>
#include "ndn.cxx/security/identity-certificate.h"

using namespace std;

namespace ndn
{

namespace security
{
  IdentityCertificate::IdentityCertificate()
  {
  }

  IdentityCertificate::IdentityCertificate(Ptr<Blob> blob)
  {
  }

  Ptr<Blob> IdentityCertificate::ToDER()
  {
    
    return NULL;
  }

  Ptr<Blob> IdentityCertificate::ToPEM()
  {
    return NULL;
  }

  Ptr<Blob> IdentityCertificate::ToXML()
  {
    return NULL;
  }

  bool IdentityCertificate::FromDER()
  {
    return false;
  }
  
  bool IdentityCertificate::FromPEM()
  {
    return false;
  }

  bool IdentityCertificate::FromXML()
  {
    return false;
  }

}//security

}//ndn
