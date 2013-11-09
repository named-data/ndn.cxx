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

#include "certificate-subdescrpt.h"
#include "certificate-extension.h"
#include "publickey.h"

namespace ndn
{

namespace security
{
  typedef vector<CertificateSubDescrypt> SubDescryptList;
  typedef vector<CertificateExtension> ExtensionList;

  /**
   * @brief Certificate class, certificate in terms of data
   *
   * Certificate is expressed as a signed data packet. This class
   * is a helper wrapper to decode the certificate data packet.
   */
  class Certificate : public Data
  {
  public:
    // enum CertificateType{
    //    IDENTITY_CERTIFICATE,
    // };

  public:
    /**
     * @brief constructor
     */
    Certificate();

    /**
     * @brief constructor
     * @param the data packet to be decoded
     */
    Certificate(const Data & data);
    
    /**
     * @brief destructor
     */
    virtual 
    ~Certificate();

    /**
     * @brief encode certificate info into content
     */
    void
    encode ();

    /**
     * @brief add subject description
     * @param descryption the description to be added
     */
    void 
    addSubjectDescription (const CertificateSubDescrypt & description) 
    { m_subjectList.push_back(description); }

    inline const SubDescryptList& 
    getSubjectDescriptionList() const
    { return m_subjectList; }

    inline SubDescryptList& 
    getSubjectDescriptionList()
    { return m_subjectList; }
   
    /**
     * @brief add certificate extension
     * @param extension the extension to be added
     */
    void 
    addExtension (const CertificateExtension & extension) 
    { m_extnList.push_back(extension); }

    inline const ExtensionList&
    getExtensionList() const
    { return m_extnList;}

    inline ExtensionList&
    getExtensionList()
    { return m_extnList;}

    void 
    setNotBefore (const Time & notBefore)
    { m_notBefore = notBefore; }

    Time & 
    getNotBefore ()
    { return m_notBefore; }
    
    const Time &
    getNotBefore () const
    { return m_notBefore; }

    void
    setNotAfter (const Time & notAfter)
    { m_notAfter = notAfter; }

    Time & 
    getNotAfter ()
    { return m_notAfter; }

    const Time &
    getNotAfter () const
    { return m_notAfter; }

    void
    setPublicKeyInfo (const Publickey & key)
    { m_key = key; }
    
    Publickey & 
    getPublicKeyInfo ()
    { return m_key; }

    const Publickey &
    getPublicKeyInfo () const
    { return m_key; }

    virtual Name 
    getPublicKeyName () const = 0;

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

    void 
    printCertificate ();

  protected:
    void
    decode();

  protected:
    SubDescryptList m_subjectList;
    Time m_notBefore;
    Time m_notAfter;
    Publickey m_key;
    ExtensionList m_extnList;
  };

}//security

}//ndn


#endif
