/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *                     Zhenkai Zhu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 *         Zhenkai Zhu <zhenkai@cs.ucla.edu>
 */

#ifndef NDN_HASH_H
#define NDN_HASH_H

#include <string.h>
#include <iostream>
#include <algorithm>
#include <boost/shared_ptr.hpp>
#include <boost/exception/all.hpp>
#include <boost/filesystem.hpp>

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"

namespace ndn
{

class Hash;
typedef boost::shared_ptr<Hash> HashPtr;

class Hash
{
public:
  static unsigned char _origin;
  static HashPtr Origin;

  Hash ()
  {
  }

  Hash (const void *buf, unsigned int length)
    : m_hash (reinterpret_cast<const char*>(buf), reinterpret_cast<const char*>(buf) + length)
  {
  }

  Hash (const Hash &otherHash)
  : m_hash (otherHash.m_hash)
  {
  }

  static HashPtr
  FromString (const std::string &hashInTextEncoding);

  static HashPtr
  FromFileContent (const boost::filesystem::path &fileName);

  static HashPtr
  FromBytes (const ndn::Blob &bytes);

  ~Hash ()
  {
  }

  Hash &
  operator = (const Hash &otherHash)
  {
    m_hash = otherHash.m_hash;
    return *this;
  }

  bool
  IsZero () const
  {
    return m_hash.empty() ||
      (m_hash.size() == 1 && m_hash[0] == 0);
  }

  bool
  operator == (const Hash &otherHash) const
  {
    return m_hash == otherHash.m_hash;
  }

  bool operator < (const Hash &otherHash) const
  {
    return std::lexicographical_compare(m_hash.begin(), m_hash.end(), otherHash.m_hash.begin(), m_hash.end());
  }

  const void *
  GetHash () const
  {
    return &m_hash[0];
  }

  unsigned int
  GetHashBytes () const
  {
    return m_hash.size();
  }

  std::string
  shortHash () const;

private:
  std::vector<char> m_hash;

  friend std::ostream &
  operator << (std::ostream &os, const Hash &digest);
};

namespace Error {
struct HashConversion : virtual boost::exception, virtual std::exception { };
}


std::ostream &
operator << (std::ostream &os, const Hash &digest);

}

#endif // NDN_HASH_H
