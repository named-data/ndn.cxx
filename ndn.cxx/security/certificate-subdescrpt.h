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


using namespace std;

namespace ndn
{

namespace security
{
  class CertificateSubDescrypt
  {
  public:
    CertificateSubDescrypt(string oid, string value);
    
    Ptr<Blob> ToDER();
    
  private:
    Ptr<vector<int> > m_oid;
    string m_value;
  };

}//security

}//ndn
