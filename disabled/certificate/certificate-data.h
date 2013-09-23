/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERTIFICATE_DATA_H
#define NDN_CERTIFICATE_DATA_H

#include <vector>
#include <string>

#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/common.h"
#include "ndn.cxx/data.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/helpers/der/der.h"

#include "certificate-subdescrpt.h"
#include "certificate-extension.h"
#include "publickey.h"


using namespace std;
using namespace boost::posix_time;

namespace ndn
{

namespace security
{
  typedef vector<CertificateSubDescrypt> SubDescryptList;
  typedef vector<CertificateExtension> ExtensionList;


  /**
   * @brief CertificateData class, the decoded content of an NDN certificate
   *
   * NDN certificate is constructed as a Data packet with a specialized content structure.
   * Given that the certificate name is expressed as the Data name and that issuer name is 
   * expressed as the KeyLocator and that signature is stored in SingatureBits of the data
   * packet, the rest part of certificate such as public key and validity is stored in this 
   * data structure. 
   */
  class CertificateData
  {
  public:
    /**
     * @brief Constructor
     */
    CertificateData () {}

    /**
     * @brief Constructor
     * @param notBefore the timestamp when the certificate becomes valid
     * @param notAfter the timestamp when the certificate expires
     * @param publickey the public key 
     */
    CertificateData (Time notBefore, Time notAfter, const Publickey & publickey);

    /**
     * @brief decode certificate data from DER blob
     * @param blob the DER blob to be decoded
     * @return the decoded certificate data
     */
    static Ptr<CertificateData>
    fromDER(Ptr<Blob> blob);

    /**
     * @brief decode certificate data from DER blob
     * @param blob the DER blob to be decoded
     * @return the decoded certificate data
     */
    static Ptr<CertificateData>
    fromDER(const Blob & blob);

    /**
     * @brief encode certificate data into DER blob
     * @return the encoded DER blob
     */
    Ptr<Blob> 
    toDERBlob ();

    /**
     * @brief encode certificate data into DER syntax tree
     * @return the encoded DER syntax tree
     */
    Ptr<der::DerNode>
    toDER ();

    /**
     * @brief add subject description
     * @param descryption the description to be added
     */
    void 
    addSubjectDescription (const CertificateSubDescrypt & description) 
    { m_subjectList.push_back(description); }
   
    /**
     * @brief add certificate extension
     * @param extension the extension to be added
     */
    void 
    addExtension (const CertificateExtension & extension) 
    { m_extnList.push_back(extension); }

    void
    setNotBefore (const Time & notBefore)
    { m_notBefore = notBefore; }

    Time & 
    getNotBefore ()
    { return m_notBefore; } 

    void
    setNotAfter (const Time & notAfter)
    { m_notAfter = notAfter; }
    
    Time & 
    getNotAfter ()
    { return m_notAfter; }

    void
    setKey (const Publickey & key)
    { m_key = key; }

    Publickey & 
    getKey () 
    { return m_key; }

    const Publickey &
    getKey () const
    { return m_key; }

    void 
    printCertificate ();

  private:
    SubDescryptList m_subjectList;
    Time m_notBefore;
    Time m_notAfter;
    Publickey m_key;
    ExtensionList m_extnList;    
  };

}//security

}//ndn

#endif
