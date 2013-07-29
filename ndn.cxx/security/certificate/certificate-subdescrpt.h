/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <vector>

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"

#include "oid.h"

using namespace std;

namespace ndn
{

namespace security
{
  class CertificateSubDescrypt
  {
  public:
    CertificateSubDescrypt(string oid, string value);
    
    CertificateSubDescrypt(const Blob & blob);

    Ptr<Blob> ToDER();

    string GetOid(){return m_oid->ToString();}

    string GetValue(){return m_value;}
    
  private:
    Ptr<OID> m_oid;
    string m_value;
  };

}//security

}//ndn
