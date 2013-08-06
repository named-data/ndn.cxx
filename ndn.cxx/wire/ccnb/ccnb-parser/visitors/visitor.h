/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _CCNB_PARSER_VISITOR_H_
#define _CCNB_PARSER_VISITOR_H_

#include "../common.h"
#include <boost/any.hpp>

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

/**
 * \ingroup ccnx-ccnb
 * \brief Visitor interface that takes one boost::any argument and returns boost::any
 *
 * \see http://www.ccnx.org/releases/latest/doc/technical/BinaryEncoding.html
 * for ccnb encoding format help
 */
class Visitor
{
public:
  virtual boost::any visit (Blob&,  boost::any)=0; ///< \brief Method accepting BLOB block  
  virtual boost::any visit (Udata&, boost::any)=0; ///< \brief Method accepting UDATA block 
  virtual boost::any visit (Tag&,   boost::any)=0; ///< \brief Method accepting TAG block   
  virtual boost::any visit (Attr&,  boost::any)=0; ///< \brief Method accepting ATTR block  
  virtual boost::any visit (Dtag&,  boost::any)=0; ///< \brief Method accepting DTAG block  
  virtual boost::any visit (Dattr&, boost::any)=0; ///< \brief Method accepting DATTR block 
  virtual boost::any visit (Ext&,   boost::any)=0; ///< \brief Method accepting EXT block

  virtual ~Visitor () { }
};                                                
                                                  
} // CcnbParser
} // wire

NDN_NAMESPACE_END
                                                  
#endif // _CCNB_PARSER_VISITOR_H_                             
