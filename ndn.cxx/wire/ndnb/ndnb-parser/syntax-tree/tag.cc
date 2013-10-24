/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "tag.h"

#include "base-attr.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

Tag::Tag (InputIterator &start, uint32_t length)
{
  m_tag.reserve (length+2); // extra byte for potential \0 at the end
  uint32_t i = 0;
  for (; !start.IsEnd () && i < (length+1); i++)
    {
      m_tag.push_back (start.ReadU8 ());
    }
  if (i < (length+1) && start.IsEnd ())
    throw NdnbDecodingException ();
  
  // parse attributes until first nested block reached
  while (!start.IsEnd () && BufferIteratorPeekU8 (start)!=NDN_CLOSE)
    {
      Ptr<Block> block = Block::ParseBlock (start);
      if (DynamicCast<BaseAttr> (block)!=0)
		m_attrs.push_back (block);
	  else
		{
		  m_nestedTags.push_back (block);
		  break;
		}
	}

  // parse the rest of nested blocks
  while (!start.IsEnd () && BufferIteratorPeekU8 (start)!=NDN_CLOSE)
    {
      Ptr<Block> block = Block::ParseBlock (start);
	  m_nestedTags.push_back (block);
    }
  
  if (start.IsEnd ()) //should not be the end
      throw NdnbDecodingException ();

  start.ReadU8 (); // read NDN_CLOSE
}

} // namespace NdnbParser
} // namespace wire

NDN_NAMESPACE_END
