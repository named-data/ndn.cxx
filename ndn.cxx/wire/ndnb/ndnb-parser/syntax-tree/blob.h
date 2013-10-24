/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_BLOB_H_
#define _NDNB_PARSER_BLOB_H_

#include "block.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndnx-ndnb
 * \brief Class to represent BLOB ndnb-encoded node
 *
 * \see http://www.ndnx.org/releases/latest/doc/technical/BinaryEncoding.html
 */
class Blob : public Block
{
public:
  /**
   * \brief Constructor that actually parsed ndnb-encoded BLOB block
   *
   * \param start  buffer iterator pointing to the first byte of BLOB data in ndnb-encoded block 
   * \param length length of data in BLOB block (extracted from the value field)
   *
   * \see http://www.ndnx.org/releases/latest/doc/technical/BinaryEncoding.html
   */
  Blob (InputIterator &start, uint32_t length);
  ~Blob ();
  
  virtual void accept( VoidNoArguVisitor &v )               { v.visit( *this ); }
  virtual void accept( VoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( NoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( Visitor &v, boost::any param ) { return v.visit( *this, param ); }

  char* m_blob; ///< \brief field holding a parsed BLOB value of the block
  uint32_t  m_blobSize; ///< @brief field representing size of the BLOB field stored
};

} // namespace NdnbParser
} // namespace wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_BLOB_H_
