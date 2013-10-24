/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_UDATA_H_
#define _NDNB_PARSER_UDATA_H_

#include "block.h"
#include <string>

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndnx-ndnb
 * \brief Class to represent UDATA ndnb-encoded node
 */
class Udata : public Block
{
public:
  /**
   * \brief Constructor that actually parsed ndnb-encoded UDATA block
   *
   * \param start  buffer iterator pointing to the first byte of string in ndnb-encoded block 
   * \param length length of data in UDATA block (extracted from the value field)
   *
   * \see http://www.ndnx.org/releases/latest/doc/technical/BinaryEncoding.html
   */
  Udata (InputIterator &start, uint32_t length);
  
  virtual void accept( VoidNoArguVisitor &v )               { v.visit( *this ); }
  virtual void accept( VoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( NoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( Visitor &v, boost::any param ) { return v.visit( *this, param ); }

  std::string m_udata; ///< \brief field holding a parsed UDATA value of the block
};

} // namespace NdnbParser
} // namespace wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_UDATA_H_
