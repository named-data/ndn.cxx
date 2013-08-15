/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_OID_H
#define NDN_CERTIFICATE_OID_H

#include <string>
#include <vector>

using namespace std;

namespace ndn
{

namespace security
{

  class OID
  {
  public:
    OID(const string & oid);

    OID(const vector<int> & oid);

    OID(const OID & oid);

    OID(const Blob & blob); //For DER

    string toString();

    Ptr<Blob> toDER();

    bool operator == (const OID & oid);

    bool operator != (const OID & oid);

  private:
    bool equal(const OID & oid);

  private:
    vector<int> m_oid;
  };

}//security

}//ndn

#endif

