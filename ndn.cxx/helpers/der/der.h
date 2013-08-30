/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_H
#define NDN_DER_H

#include <vector>
#include <string>
#include <sstream>

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/helpers/oid.h"

#include "visitor/visitor.h"
#include "visitor/void-visitor.h"
#include "visitor/no-argu-visitor.h"
#include "visitor/void-no-argu-visitor.h"

using namespace std;

namespace ndn
{

namespace der
{
  enum DerType {
    DER_EOC = 0,
    DER_BOOLEAN = 1,
    DER_INTEGER = 2,
    DER_BIT_STRING = 3,
    DER_OCTET_STRING = 4,
    DER_NULL = 5,
    DER_OBJECT_IDENTIFIER = 6,
    DER_OBJECT_DESCRIPTOR = 7,
    DER_EXTERNAL = 40,
    DER_REAL = 9,
    DER_ENUMERATED = 10,
    DER_EMBEDDED_PDV = 43,
    DER_UTF8_STRING = 12,
    DER_RELATIVE_OID = 13,
    DER_SEQUENCE = 48,
    DER_SET = 49,
    DER_NUMERIC_STRING = 18,
    DER_PRINTABLE_STRING = 19,
    DER_T61_STRING = 20,
    DER_VIDEOTEX_STRING = 21,
    DER_IA5_STRING = 22,
    DER_UTC_TIME = 23,
    DER_GENERALIZED_TIME = 24,
    DER_GRAPHIC_STRING = 25,
    DER_VISIBLE_STRING = 26,
    DER_GENERAL_STRING = 27,
    DER_UNIVERSAL_STRING = 28,
    DER_CHARACTER_STRING = 29,
    DER_BMP_STRING = 30,
  };

  class DerComplex;

  class DerNode
  {
  public:
    DerNode ();

    DerNode (DerType type);

    DerNode (InputIterator &start);

    virtual
    ~DerNode ();

    virtual int
    getSize()
    { return m_header.size() + m_payload.size(); }

    virtual void 
    encode(OutputIterator & start);
    
    void
    setParent(DerComplex * parent)
    { m_parent = parent; }

    static Ptr<DerNode>
    parse(InputIterator & start);

    const Blob & 
    getHeader() const
    { return m_header; }

    Blob &
    getHeader()
    { return m_header; }

    const Blob &
    getPayload() const
    { return m_payload; }
    
    Blob & 
    getPayload() 
    { return m_payload; }

    const DerType &
    getType()
    { return m_type; }

    virtual Ptr<Blob>
    getRaw()
    { 
      Ptr<Blob> blob = Ptr<Blob>::Create();
      blob->insert(blob->end(), m_header.begin(), m_header.end());
      blob->insert(blob->end(), m_payload.begin(), m_payload.end());

      return blob;
    }

    virtual void accept(VoidNoArguVisitor & visitor) = 0;
    virtual void accept(VoidVisitor & visitor, boost::any param) = 0;
    virtual boost::any accept(NoArguVisitor & visitor) = 0;
    virtual boost::any accept(Visitor & visitor, boost::any param) = 0;
    
  protected:
    void
    decode(InputIterator & start);

    void
    encodeHeader(int size);

    int 
    decodeHeader(InputIterator & start);

  protected:
    DerType m_type;
    Blob m_header;
    Blob m_payload;
    DerComplex * m_parent;
  };


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
    { return m_nodeList; }

    DerNodePtrList &
    getChildren()
    { return m_nodeList; }

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



  class DerByteString : public DerNode
  {
  public:
    DerByteString(const string & str, DerType type);

    DerByteString(const Blob & blob, DerType type);

    DerByteString(InputIterator &start);

    virtual
    ~DerByteString();
  };


  //0x01  
  class DerBool : public DerNode
  {
  public:
    DerBool(bool value);

    DerBool(InputIterator & start);

    virtual
    ~DerBool();

    virtual void accept(VoidNoArguVisitor & visitor)               {        visitor.visit(*this);        }
    virtual void accept(VoidVisitor & visitor, boost::any param)   {        visitor.visit(*this, param); }
    virtual boost::any accept(NoArguVisitor & visitor)             { return visitor.visit(*this);        }
    virtual boost::any accept(Visitor & visitor, boost::any param) { return visitor.visit(*this, param); }

  };
  
  //0x02  
  class DerInteger : public DerNode
  {
  public:
    DerInteger(const Blob & blob);

    DerInteger(InputIterator &start);

    virtual 
    ~DerInteger();

    virtual void accept(VoidNoArguVisitor & visitor)               {        visitor.visit(*this);        }
    virtual void accept(VoidVisitor & visitor, boost::any param)   {        visitor.visit(*this, param); }
    virtual boost::any accept(NoArguVisitor & visitor)             { return visitor.visit(*this);        }
    virtual boost::any accept(Visitor & visitor, boost::any param) { return visitor.visit(*this, param); }

  };

  //0x03
  class DerBitString : public DerNode
  {
  public:
    DerBitString(const Blob & blob, uint8_t paddingLen);

    DerBitString(InputIterator &start);
    
    virtual
    ~DerBitString();

    virtual void accept(VoidNoArguVisitor & visitor)               {        visitor.visit(*this);        }
    virtual void accept(VoidVisitor & visitor, boost::any param)   {        visitor.visit(*this, param); }
    virtual boost::any accept(NoArguVisitor & visitor)             { return visitor.visit(*this);        }
    virtual boost::any accept(Visitor & visitor, boost::any param) { return visitor.visit(*this, param); }

  };

  //0x04
  class DerOctetString : public DerByteString
  {
  public:
    DerOctetString(const string & str);
    
    DerOctetString(const Blob & blob);

    DerOctetString(InputIterator &start);

    virtual
    ~DerOctetString();

    virtual void accept(VoidNoArguVisitor & visitor)               {        visitor.visit(*this);        }
    virtual void accept(VoidVisitor & visitor, boost::any param)   {        visitor.visit(*this, param); }
    virtual boost::any accept(NoArguVisitor & visitor)             { return visitor.visit(*this);        }
    virtual boost::any accept(Visitor & visitor, boost::any param) { return visitor.visit(*this, param); }

  };


  //0x05
  class DerNull : public DerNode
  {
  public:
    DerNull();

    DerNull(InputIterator &start);
    
    virtual
    ~DerNull();

    virtual void accept(VoidNoArguVisitor & visitor)               {        visitor.visit(*this);        }
    virtual void accept(VoidVisitor & visitor, boost::any param)   {        visitor.visit(*this, param); }
    virtual boost::any accept(NoArguVisitor & visitor)             { return visitor.visit(*this);        }
    virtual boost::any accept(Visitor & visitor, boost::any param) { return visitor.visit(*this, param); }

  };


  //0x06
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


  //0x10
  class DerSequence : public DerComplex
  {
  public:
    DerSequence ();

    DerSequence (InputIterator &start);
    
    virtual
    ~DerSequence ();

    virtual void accept(VoidNoArguVisitor & visitor)               {        visitor.visit(*this);        }
    virtual void accept(VoidVisitor & visitor, boost::any param)   {        visitor.visit(*this, param); }
    virtual boost::any accept(NoArguVisitor & visitor)             { return visitor.visit(*this);        }
    virtual boost::any accept(Visitor & visitor, boost::any param) { return visitor.visit(*this, param); }

  };

  //0x13
  class DerPrintableString : public DerByteString
  {
  public:
    DerPrintableString(const string & str);

    DerPrintableString(const Blob & blob);

    DerPrintableString(InputIterator &start);

    virtual 
    ~DerPrintableString();

    virtual void accept(VoidNoArguVisitor & visitor)               {        visitor.visit(*this);        }
    virtual void accept(VoidVisitor & visitor, boost::any param)   {        visitor.visit(*this, param); }
    virtual boost::any accept(NoArguVisitor & visitor)             { return visitor.visit(*this);        }
    virtual boost::any accept(Visitor & visitor, boost::any param) { return visitor.visit(*this, param); }
  };

  //0x1b
  class DerGtime : public DerNode
  {
  public:
    DerGtime(const Time & time);

    DerGtime(InputIterator &start);
    
    virtual 
    ~DerGtime();

    virtual void accept(VoidNoArguVisitor & visitor)               {        visitor.visit(*this);        }
    virtual void accept(VoidVisitor & visitor, boost::any param)   {        visitor.visit(*this, param); }
    virtual boost::any accept(NoArguVisitor & visitor)             { return visitor.visit(*this);        }
    virtual boost::any accept(Visitor & visitor, boost::any param) { return visitor.visit(*this, param); }

  };
  
}//der

}//ndn



#endif
