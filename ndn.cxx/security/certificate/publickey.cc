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
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/helpers/der/visitor/publickey-visitor.h"

#include "logging.h"

INIT_LOGGER ("ndn.security.Publickey");

using namespace std;

namespace ndn
{

namespace security
{
  Publickey::Publickey (const OID & algorithm, const Blob & keyBlob)
    : m_algorithm(algorithm)
    , m_key(keyBlob.buf(), keyBlob.size())
  {}


  Publickey::Publickey (const Publickey & publickey)
    :m_algorithm(publickey.m_algorithm),
     m_key(publickey.m_key.buf(), publickey.m_key.size())
  {}

  Ptr<der::DerNode>
  Publickey::toDER()
  {
    boost::iostreams::stream
      <boost::iostreams::array_source> is (m_key.buf (), m_key.size ());

    return der::DerNode::parse(reinterpret_cast<InputIterator &> (is));
  }

  Ptr<Publickey>
  Publickey::fromDER(Ptr<Blob> blob)
  {
    return fromDER(*blob);
  }

  Ptr<Publickey>
  Publickey::fromDER(const Blob& blob)
  {
    boost::iostreams::stream
      <boost::iostreams::array_source> is (blob.buf (), blob.size ());

    Ptr<der::DerNode> root = der::DerNode::parse(reinterpret_cast<InputIterator &> (is));
    der::PublickeyVisitor pubkeyVisitor;
    return boost::any_cast<Ptr<Publickey> >(root->accept(pubkeyVisitor));
  }

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

}//security

}//ndn
