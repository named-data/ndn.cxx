/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _CCNB_PARSER_NO_ARGU_VISITOR_H_
#define _CCNB_PARSER_NO_ARGU_VISITOR_H_

#include "../common.h"
#include <boost/any.hpp>

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

/**
 * \ingroup ccnx-ccnb
 * \brief Visitor interface that takes no arguments and returns boost::any
 *
 * \see http://www.ccnx.org/releases/latest/doc/technical/BinaryEncoding.html
 * for ccnb encoding format help
 */
class NoArguVisitor
{
public:
  virtual boost::any visit (Blob& )=0; ///< \brief Method accepting BLOB block  
  virtual boost::any visit (Udata&)=0; ///< \brief Method accepting UDATA block 
  virtual boost::any visit (Tag&  )=0; ///< \brief Method accepting TAG block   
  virtual boost::any visit (Attr& )=0; ///< \brief Method accepting ATTR block  
  virtual boost::any visit (Dtag& )=0; ///< \brief Method accepting DTAG block  
  virtual boost::any visit (Dattr&)=0; ///< \brief Method accepting DATTR block 
  virtual boost::any visit (Ext&  )=0; ///< \brief Method accepting EXT block

  virtual ~NoArguVisitor () { }
};
  
} // CcnbParser
} // wire

NDN_NAMESPACE_END

#endif // _CCNB_PARSER_NO_ARGU_VISITOR_H_
