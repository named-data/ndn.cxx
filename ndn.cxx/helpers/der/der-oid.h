/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_OID_H
#define NDN_DER_OID_H

#include "der-node.h"

#include "ndn.cxx/helpers/oid.h"

#include <sstream>

namespace ndn
{

namespace der
{
  class DerOid : public DerNode
  {
  public:
    DerOid (const OID & oid);
    
    DerOid (const string & oidStr);

    DerOid (const vector<int> & value);

    DerOid (InputIterator & start);
    
    virtual
    ~DerOid ();
    
    virtual void accept(VoidNoArguVisitor & visitor)               {        visitor.visit(*this);        }
    virtual void accept(VoidVisitor & visitor, boost::any param)   {        visitor.visit(*this, param); }
    virtual boost::any accept(NoArguVisitor & visitor)             { return visitor.visit(*this);        }
    virtual boost::any accept(Visitor & visitor, boost::any param) { return visitor.visit(*this, param); }

    int 
    decode128 (int & offset);

  private:
    void 
    prepareEncoding (const vector<int> & value);

    void 
    encode128 (int value, ostringstream & os);    
  };

}//der

}//ndn

#endif
