/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_COMPLEX_H
#define NDN_DER_COMPLEX_H

#include "der-node.h"

namespace ndn
{

namespace der
{
  typedef vector<Ptr<DerNode> > DerNodePtrList;

  class DerComplex : public DerNode
  {
  public:
    DerComplex ();
    
    DerComplex (DerType type);

    DerComplex (InputIterator & start);

    virtual 
    ~DerComplex ();

    virtual int
    getSize ();

    void 
    addChild (Ptr<DerNode> nodePtr, bool notifyParent = true);

    virtual void
    encode (OutputIterator & start);

    const DerNodePtrList &
    getChildren() const
    {
      return m_nodeList;
    }

    DerNodePtrList &
    getChildren()
    {
      return m_nodeList;
    }

    virtual Ptr<Blob>
    getRaw();

  private:
    void
    updateSize ();

    void
    setChildChanged ();

  private:
    bool m_childChanged;
    int m_size;
    DerNodePtrList m_nodeList;
  };

}//der

}//ndn

#endif
