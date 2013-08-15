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

  Publickey::Publickey(const Blob & blob, bool pem)
  {
    bool res = false;

    m_key = Ptr<Blob>(new Blob(blob.buf(), blob.size()));

    if(pem)
      res = fromPEM(blob);
    else
      res = fromDER(blob);

    if(!res){
      throw SecException("public key is not created!");
    }
  }

  Ptr<Blob> Publickey::getDigest() const
  {
    CryptoPP::SHA256 hash;
    byte digest[CryptoPP::SHA256::DIGESTSIZE];

    hash.CalculateDigest(digest, (byte *)m_key->buf(), m_key->size());
    
    return Ptr<Blob>( new Blob (digest, CryptoPP::SHA256::DIGESTSIZE));
  }

  bool Publickey::fromDER(const Blob & blob)
  {
    DERendec endec;
    Ptr<vector<Ptr<Blob> > > sequence = endec.decodeSequenceDER(blob);

    m_algorithm = Ptr<OID>(new OID(*endec.decodeSequenceDER(*sequence->at(0))->at(0)));
      
    m_keyBits = sequence->at(1);
    
    return true;
  }
    
  bool Publickey::fromPEM(const Blob & blob)
  {
    //TODO:
    _LOG_DEBUG("PEM format is not supported yet!");
    return false;
  }


}//security

}//ndn
