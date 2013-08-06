/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _CCNB_PARSER_DTAG_H_
#define _CCNB_PARSER_DTAG_H_

#include "base-tag.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

/**
 * \ingroup ccnx-ccnb
 * \brief Class to represent DTAG ccnb-encoded node
 *
 * \see http://www.ccnx.org/releases/latest/doc/technical/BinaryEncoding.html
 */
class Dtag : public BaseTag
{
public:
  /**
   * \brief Constructor that actually parsed ccnb-encoded DTAG block
   *
   * \param start buffer iterator pointing to the first nesting block or closing tag
   * \param dtag  dictionary code of DTAG (extracted from the value field)
   *
   * DTAG parsing is slightly hacked to provide memory optimization
   * for NS-3 simulations.  Parsing will be stopped after encountering
   * "Content" dtag.  Actual content (including virtual payload) will
   * be stored in Packet buffer
   *
   * \see http://www.ccnx.org/releases/latest/doc/technical/BinaryEncoding.html
   */
  Dtag (InputIterator &start, uint32_t dtag);

  virtual void accept( VoidNoArguVisitor &v )               { v.visit( *this ); }
  virtual void accept( VoidVisitor &v, boost::any param )   { v.visit( *this, param ); }
  virtual boost::any accept( NoArguVisitor &v )             { return v.visit( *this ); }
  virtual boost::any accept( Visitor &v, boost::any param ) { return v.visit( *this, param ); }

  uint32_t m_dtag; ///< \brief Dictionary code for DTAG
};

} // namespace CcnbParser
} // namespace wire

NDN_NAMESPACE_END

#endif // _CCNB_PARSER_DTAG_H_
