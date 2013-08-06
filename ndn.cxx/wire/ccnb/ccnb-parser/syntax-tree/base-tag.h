/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _CCNB_PARSER_BASE_TAG_H_
#define _CCNB_PARSER_BASE_TAG_H_

#include "block.h"
#include <list>

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

/**
 * \ingroup ccnx-ccnb
 * \brief Virtual base class providing a common storage for TAG
 * and DTAG ccnb-encoded blocks
 *
 * \see http://www.ccnx.org/releases/latest/doc/technical/BinaryEncoding.html
 */
class BaseTag : public Block
{
public:
  std::list<Ptr<Block> > m_attrs;      ///< \brief List of attributes, associated with this tag
  std::list<Ptr<Block> > m_nestedTags; ///< \brief List of nested tags
  
protected:
  /**
   * \brief Default constructor
   */
  BaseTag() { }
};

} // namespace CcnbParser
} // namespace wire

NDN_NAMESPACE_END

#endif // _CCNB_PARSER_BASE_TAG_H_

