/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _CCNB_PARSER_UINT32T_BLOB_VISITOR_H_
#define _CCNB_PARSER_UINT32T_BLOB_VISITOR_H_

#include "no-argu-depth-first-visitor.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

/**
 * \ingroup ccnx-ccnb
 * \brief Visitor to obtain nonce value from BLOB block
 *
 * Note, only first 32 bits will be actually parsed into nonce. If
 * original Nonce contains more, the rest will be ignored
 *
 * Will return empty boost::any() if called on anything except BLOB block
 */
class Uint32tBlobVisitor : public NoArguDepthFirstVisitor
{
public:
  virtual boost::any visit (Blob &n); 
  virtual boost::any visit (Udata &n); ///< Throws parsing error if BLOB object is encountered
};

} // CcnbParser
} // wire

NDN_NAMESPACE_END

#endif // _CCNB_PARSER_UINT32T_BLOB_VISITOR_H_
