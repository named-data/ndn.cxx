/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <cryptopp/sha.h>


#include "publickey.h"
#include "ndn.cxx/security/encoding/der.h"
#include "ndn.cxx/security/exception.h"

#include "logging.h"

INIT_LOGGER ("ndn.security.Publickey");

using namespace std;

namespace ndn
{

namespace security
{
  Publickey::Publickey (const Blob & blob, bool pem)
    :m_key(blob.buf(), blob.size())
  {
    if(pem)
      fromPEM(blob);
    else
      fromDER(blob);
  }

  Publickey::Publickey (const Publickey & publickey)
    :m_algorithm(publickey.m_algorithm),
     m_key(publickey.m_key.buf(), publickey.m_key.size())
  {}

  Ptr<const Blob> 
  Publickey::getDigest (DigestAlgorithm digestAlgo) const
  {
    
    if(DIGEST_SHA256 == digestAlgo)
      {
        CryptoPP::SHA256 hash;
        byte digest[CryptoPP::SHA256::DIGESTSIZE];

        hash.CalculateDigest(digest, (byte *)m_key.buf(), m_key.size());
    
        return Ptr<const Blob>( new Blob (digest, CryptoPP::SHA256::DIGESTSIZE));
      }
    else
      throw UnrecognizedDigestAlgoException("Wrong format!");
  }

  void 
  Publickey::fromDER (const Blob & blob)
  {
    Ptr<Blob>(new Blob(blob.buf(), blob.size()));

    DERendec endec;
    Ptr<vector<Ptr<Blob> > > sequence = endec.decodeSequenceDER(blob);

    m_algorithm = *endec.decodeSequenceDER(*sequence->at(0))->at(0);
  }
    
  void 
  Publickey::fromPEM (const Blob & blob)
  {
    //TODO:
    throw UnrecognizedKeyFormatException("PEM is not supported in Publickey");
  }


}//security

}//ndn
