/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "void-no-argu-depth-first-visitor.h"

#include "../syntax-tree/blob.h"
#include "../syntax-tree/udata.h"
#include "../syntax-tree/tag.h"
#include "../syntax-tree/dtag.h"
#include "../syntax-tree/attr.h"
#include "../syntax-tree/dattr.h"
#include "../syntax-tree/ext.h"

#include <boost/foreach.hpp>

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

void
VoidNoArguDepthFirstVisitor::visit (Blob &n)
{
  // Buffer n.m_blob;
}
 
void
VoidNoArguDepthFirstVisitor::visit (Udata &n)
{
  // std::string n.m_udata;
}
 
void
VoidNoArguDepthFirstVisitor::visit (Tag &n)
{
  // std::string n.m_tag;
  // std::list<Ptr<Block> > n.m_attrs;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_attrs)
    {
      block->accept (*this);
    }
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedTags)
    {
      block->accept (*this);
    }
}
 
void
VoidNoArguDepthFirstVisitor::visit (Dtag &n)
{
  // uint32_t n.m_dtag;
  // std::list<Ptr<Block> > n.m_attrs;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_attrs)
    {
      block->accept (*this);
    }
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedTags)
    {
      block->accept (*this);
    }
}
 
void
VoidNoArguDepthFirstVisitor::visit (Attr &n)
{
  // std::string n.m_attr;
  // Ptr<Udata> n.m_value;
}
 
void
VoidNoArguDepthFirstVisitor::visit (Dattr &n)
{
  // uint32_t n.m_dattr;
  // Ptr<Udata> n.m_value;
}
 
void
VoidNoArguDepthFirstVisitor::visit (Ext &n)
{
  // uint64_t n.m_extSubtype;
}

} // NdnbParser
} // wire

NDN_NAMESPACE_END
