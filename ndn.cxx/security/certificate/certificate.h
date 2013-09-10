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
  /**
   * @brief Certificate class, certificate in terms of data
   *
   * Certificate is expressed as a signed data packet. This class
   * is a helper wrapper to decode the certificate data packet.
   */
  class Certificate : public Data
  {
  public:
    enum CertificateType{
      IDENTITY_CERT,
    };

  public:
    /**
     * @brief constructor
     */
    Certificate() {}

    /**
     * @brief constructor
     * @param the data packet to be decoded
     */
    Certificate(const Data & data);
    
    /**
     * @brief destructor
     */
    virtual ~Certificate();

    Time & 
    getNotBefore();
    
    const Time &
    getNotBefore() const;

    Time & 
    getNotAfter();

    const Time &
    getNotAfter() const;
    
    Publickey & 
    getPublicKeyInfo();

    const Publickey & 
    getPublicKeyInfo() const;

    /**
     * @brief check if the certificate is valid
     * @return true if current time is early than notBefore
     */
    bool 
    isTooEarly();

    /**
     * @brief check if the certificate is valid
     * @return true if current time is late than notAfter
     */
    bool
    isTooLate();

  private:
    Ptr<CertificateData> m_certData;
  };

}//security

}//ndn


#endif
