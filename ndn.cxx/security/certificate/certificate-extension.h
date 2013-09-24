/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_EXTENSION_H
#define NDN_CERTIFICATE_EXTENSION_H

#include <vector>
#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"

#include "ndn.cxx/helpers/oid.h"
#include "ndn.cxx/helpers/der/der.h"

using namespace std;

namespace ndn
{

namespace security
{
  /**
   * @brief CertificateExtension class, Extension entry in certificate 
   */
  class CertificateExtension
  {
  public:
    /**
     * @brief constructor
     * @param oid the oid of subject description entry
     * @param critical if true, the entension must be handled
     * @param value the extension value
     */
    CertificateExtension (const string & oid, const bool & critical, const Blob & value);

    /**
     * @brief constructor
     * @param oid the oid of subject description entry
     * @param critical if true, the entension must be handled
     * @param value the extension value
     */
    CertificateExtension (const OID & oid, const bool & critical, const Blob & value);

    virtual
    ~CertificateExtension () {}

    /**
     * @brief encode the object into DER syntax tree
     * @return the encoded DER syntax tree
     */
    Ptr<der::DerNode> 
    toDER();
      
  protected:
    OID m_extnID;
    bool m_critical;
    Blob m_extnValue;
  };
  
}//security

}//ndn

#endif
