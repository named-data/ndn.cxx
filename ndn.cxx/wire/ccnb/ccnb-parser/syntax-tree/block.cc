/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "block.h"

#include "blob.h"
#include "udata.h"
#include "tag.h"
#include "dtag.h"
#include "attr.h"
#include "dattr.h"
#include "ext.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

/// @cond include_hidden
const uint8_t NDN_TT_BITS = 3;
const uint8_t NDN_TT_MASK = ((1 << NDN_TT_BITS) - 1);
const uint8_t NDN_MAX_TINY= ((1 << (7-NDN_TT_BITS)) - 1);
const uint8_t NDN_TT_HBIT = ((uint8_t)(1 << 7));
/// @endcond

// int Block::counter = 0;

Ptr<Block> Block::ParseBlock (InputIterator &start, bool dontParseBlock)
{
  // std::cout << "<< pos: " << counter << "\n";
  uint32_t value = 0;

  // We will have problems if length field is more than 32 bits. Though it's really impossible
  uint8_t byte = 0;
  while (!start.IsEnd() && !(byte & NDN_TT_HBIT))
    {
      value <<= 7;
      value += byte;
      byte = start.ReadU8 ();
      // Block::counter ++;
    }
  if (start.IsEnd())
    CcnbDecodingException ();

  if (dontParseBlock)
    {
      return 0;
    }
  
  value <<= 4;
  value += ( (byte&(~NDN_TT_HBIT)) >> 3);
  
  /**
   * Huh. After fighting with NS-3, it became apparent that Create<T>(...) construct
   * doesn't work with references.  Just simply doesn't work.  wtf?
   */
  switch (byte & NDN_TT_MASK)
    {
    case NDN_BLOB:
      return Ptr<Blob> (new Blob(start, value), false);
    case NDN_UDATA:
      return Ptr<Udata> (new Udata(start, value), false);
    case NDN_TAG:
      return Ptr<Tag> (new Tag(start, value), false);
    case NDN_ATTR:
      return Ptr<Attr> (new Attr(start, value), false);
    case NDN_DTAG:
      return Ptr<Dtag> (new Dtag(start, value), false);
    case NDN_DATTR:
      return Ptr<Dattr> (new Dattr(start, value), false);
    case NDN_EXT:
      return Ptr<Ext> (new Ext(start, value), false);
    default:
      throw CcnbDecodingException ();
    }
}

Block::~Block ()
{
}

} // namespace CcnbParser
} // namespace wire

NDN_NAMESPACE_END
