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

#include <string>
#include <vector>

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"

#include "oid.h"

using namespace std;


namespace ndn
{

namespace security
{
  class DERendec{
  public:
    DERendec();
    
    Ptr<Blob> 
    encodeStringDER(const Blob & str);
    
    Ptr<Blob> 
    decodeStringDER(const Blob & blob);

    Ptr<Blob> 
    encodeBitStringDER(const Blob & bits, int paddingLen);

    Ptr<Blob> 
    decodeBitStringDER(const Blob & blob, int & paddingLen);

    Ptr<Blob> 
    encodePrintableStringDER(const string & str);
    
    Ptr<string> 
    decodePrintableStringDER(const Blob & blob);

    Ptr<Blob> 
    encodeGTimeDER(const Time & str);

    Time 
    decodeGTimeDER(const Blob & blob);

    Ptr<Blob> 
    encodeIntegerDER(const Blob & blob);
    
    Ptr<Blob> 
    decodeIntegerDER(const Blob & blob);

    Ptr<Blob> 
    encodeSequenceDER(vector<Ptr<Blob> > & components);

    Ptr<vector<Ptr<Blob> > > 
    decodeSequenceDER(const Blob & blob);

    Ptr<Blob> 
    encodeBoolDER(bool b);

    bool 
    decodeBoolDER(const Blob & blob);

    Ptr<Blob> 
    encodeNULLDER();

    void 
    decodeNULLDER(const Blob & blob);

    void 
    printDecoded(const Blob & blob, string indent, int offset);

    void 
    printBlob(const Blob & blob, string indent);

    Ptr<Blob> 
    encodeSize(int size);

    int 
    decodeSize(const Blob & blob, int & offset);
    
    Ptr<Blob> 
    encodeString(const Blob & str, int type);

    Ptr<Blob> 
    encodeInteger128(int i);

    int 
    decodeInteger128(const Blob & blob, int & offset);
			 
  private:
    Ptr<Blob> encodeInteger32bDER(int32_t i);

  private:
    bool m_littleEndian;
  };

}//security

}//ndn

#endif

