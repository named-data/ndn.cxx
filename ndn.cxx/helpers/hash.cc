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

#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreorder"
#elif __GNUC__
#pragma GCC diagnostic ignored "-Wreorder"
#endif

#include "hash.h"
#include "ndn.cxx/helpers/uri.h"

#include <boost/assert.hpp>
#include <boost/throw_exception.hpp>
#include <boost/make_shared.hpp>
#include <boost/lexical_cast.hpp>
#include <fstream>

#include <cryptopp/sha.h>

typedef boost::error_info<struct tag_errmsg, std::string> errmsg_info_str;
typedef boost::error_info<struct tag_errmsg, int> errmsg_info_int;

#include <boost/filesystem/fstream.hpp>

using namespace boost;
using namespace boost::archive::iterators;
using namespace std;
namespace fs = boost::filesystem;

namespace ndn
{

std::ostream &
operator << (std::ostream &os, const Hash &hash)
{
  if (hash.m_hash.empty())
    return os;

  ostreambuf_iterator<char> out_it (os); // ostream iterator
  // need to encode to base64

  copy (detail::string_from_binary (hash.m_hash.begin()),
        detail::string_from_binary (hash.m_hash.end()),
        out_it);

  return os;
}

std::string
Hash::shortHash () const
{
  return lexical_cast<string> (*this).substr (0, 10);
}


unsigned char Hash::_origin = 0;
HashPtr Hash::Origin(new Hash(&Hash::_origin, sizeof(unsigned char)));

HashPtr
Hash::FromString (const std::string &hashInTextEncoding)
{
  HashPtr retval = boost::make_shared<Hash> ();

  if (hashInTextEncoding.size () == 0)
    {
      return retval;
    }

  if (hashInTextEncoding.size () > CryptoPP::SHA256::DIGESTSIZE * 2)
    {
      cerr << "Input hash is too long. Returning an empty hash" << endl;
      return retval;
    }

  retval->m_hash.resize (CryptoPP::SHA256::DIGESTSIZE);

  copy (detail::string_to_binary (hashInTextEncoding.begin ()),
        detail::string_to_binary (hashInTextEncoding.end ()),
        retval->m_hash.begin ());
  
  return retval;
}

HashPtr
Hash::FromFileContent (const fs::path &filename)
{
  HashPtr retval = boost::make_shared<Hash> ();

  CryptoPP::SHA256 hash;
  retval->m_hash.resize (CryptoPP::SHA256::DIGESTSIZE);

  fs::ifstream iff (filename, std::ios::in | std::ios::binary);
  while (iff.good ())
    {
      char buf[1024];
      iff.read (buf, 1024);

      hash.Update (reinterpret_cast<const unsigned char*> (buf), iff.gcount ());
    }
  hash.Final (reinterpret_cast<unsigned char*> (&retval->m_hash[0]));

  return retval;
}

HashPtr
Hash::FromBytes (const ndn::Blob &bytes)
{
  HashPtr retval = boost::make_shared<Hash> ();
  retval->m_hash.resize (CryptoPP::SHA256::DIGESTSIZE);

  CryptoPP::SHA256 hash;
  hash.CalculateDigest (reinterpret_cast<unsigned char*> (&retval->m_hash[0]),
                        reinterpret_cast<const unsigned char*> (bytes.buf()), bytes.size());

  return retval;
}

} // ndn
