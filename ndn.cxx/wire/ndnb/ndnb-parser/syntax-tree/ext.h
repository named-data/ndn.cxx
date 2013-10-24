/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_EXT_H_
#define _NDNB_PARSER_EXT_H_

#include "block.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndnx-ndnb
 * \brief Class to represent EXT ndnb-encoded node
 *
 * \see http://www.ndnx.org/releases/latest/doc/technical/BinaryEncoding.html
 */
class Ext : public Block
{
public:
  /**
   * \brief Constructor that actually parsed ndnb-encoded DTAG block
   *
   * \param start buffer iterator pointing to the next byte past EXT block
   * \param extSubtype extension type (extracted from the value field)
   *
   * \see http://www.ndnx.org/releases/latest/doc/technical/BinaryEncoding.html
   */
  Ext (InputIterator &start, uint32_t extSubtype);

  virtual void accept( VoidNoArguVisitor &v )               { v.visit( *this ); }
  virtual void accept( VoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( NoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( Visitor &v, boost::any param ) { return v.visit( *this, param ); }

  uint64_t m_extSubtype; ///< \brief Extension type
};

} // namespace NdnbParser
} // namespace wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_EXT_H_
