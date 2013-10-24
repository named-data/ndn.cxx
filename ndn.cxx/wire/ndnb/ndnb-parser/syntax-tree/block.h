/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_BLOCK_H_
#define _NDNB_PARSER_BLOCK_H_

#include "../common.h"

// visitors
#include "../visitors/void-no-argu-visitor.h"
#include "../visitors/void-visitor.h"
#include "../visitors/no-argu-visitor.h"
#include "../visitors/visitor.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndnx-ndnb
 * \brief Base class for ndnb-encoded node
 *
 * This class provides a static method to create a new block
 * (recursively) from the stream
 *
 * \see http://www.ndnx.org/releases/latest/doc/technical/BinaryEncoding.html
 */
class Block : public SimpleRefCount<Block>
{
public:
  // static int counter;
  /**
   * \brief Parsing stream (recursively) and creating a parsed BLOCK
   * object
   *
   * \param start buffer iterator pointing to the start position for parsing
   * \param dontParseBlock parameter to indicate whether the block should not be parsed, just length
   *                       of the block should be consumed (e.g., in case of "cheating" with content of Data packets)
   * \returns parsed ndnb-encoded block, that could contain more block inside
   */
  static Ptr<Block>
  ParseBlock (InputIterator &start, bool dontParseBlock = false);

  virtual ~Block ();
  
  virtual void accept( VoidNoArguVisitor &v )               = 0; ///< @brief Accept visitor void(*)()
  virtual void accept( VoidVisitor &v, boost::any param )   = 0; ///< @brief Accept visitor void(*)(boost::any)
  virtual boost::any accept( NoArguVisitor &v )             = 0; ///< @brief Accept visitor boost::any(*)()
  virtual boost::any accept( Visitor &v, boost::any param ) = 0; ///< @brief Accept visitor boost::any(*)(boost::any)
};

/**
 * @brief Necessary until InputIterator gets PeekU8 call
 * @param i buffer iterator
 * @return peeked uint8_t value
 */
inline
uint8_t
BufferIteratorPeekU8 (InputIterator &i)
{
  uint8_t ret = i.ReadU8 ();
  i.Prev ();
  return ret;
}

} // namespace NdnbParser
} // namespace wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_BLOCK_H_
