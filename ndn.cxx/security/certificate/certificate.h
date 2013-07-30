/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_H
#define NDN_CERTIFICATE_H

#include "ndn.cxx/data.h"
#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/name.h"

#include "certificate-data.h"

namespace ndn
{

namespace security
{

  class Certificate : public Data
  {
  public:
    Certificate(const Data & data);

    Name 
    getCertName();

    int 
    getSeqNumber();

    Time & 
    getNotBefore();

    Time & 
    getNotAfter();
    
    Publickey & 
    getPublicKeyInfo();

    

  private:
    Ptr<CertificateData> m_certData;
  };

}//security

}//ndn


#endif
