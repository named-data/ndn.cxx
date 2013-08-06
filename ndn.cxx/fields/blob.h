/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *                     Zhenkai Zhu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_BLOB_H
#define NDN_BLOB_H

#include <vector>
#include <cstddef>
#include "ndn.cxx/common.h"

#include <boost/iostreams/detail/ios.hpp>
#include <boost/iostreams/categories.hpp>
#include <boost/iostreams/stream.hpp>

namespace ndn {

/**
 * @brief Class representing a general-use binary blob
 */
class Blob : public std::vector<char>
{
public:
  /**
   * @brief Creates an empty blob
   */
  Blob ()
  {
  }

  Blob (const void *buf, size_t length)
    : std::vector<char> (reinterpret_cast<const char*> (buf), reinterpret_cast<const char*> (buf) + length)
  {
  }
  
  /**
   * @brief Get pointer to the first byte of the binary blob
   */
  inline char*
  buf ()
  {
    return &front ();
  }

  /**
   * @brief Get const pointer to the first byte of the binary blob
   */
  inline const char*
  buf () const
  {
    return &front ();
  }
};

namespace iostreams
{

class blob_append_device {
public:
  typedef char  char_type;
  typedef boost::iostreams::sink_tag       category;
  
  blob_append_device (Blob& container)
  : m_container (container)
  {
  }
  
  std::streamsize
  write(const char_type* s, std::streamsize n)
  {
    std::copy (s, s+n, std::back_inserter(m_container));
    return n;
  }
  
protected:
  Blob& m_container;
};

} // iostreams

struct blob_stream : public boost::iostreams::stream<iostreams::blob_append_device>
{
  blob_stream ()
    : m_buf (Create<Blob> ())
    , m_device (*m_buf)
  {
    open (m_device);
  }

  Ptr<Blob>
  buf ()
  {
    flush ();
    return m_buf;
  }

private:
  Ptr<Blob> m_buf;
  iostreams::blob_append_device m_device;
};


} // ndn

#endif // NDN_BLOB_H
