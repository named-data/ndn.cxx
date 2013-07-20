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

using namespace std;


namespace ndn
{

namespace security
{
  class DERendec{
  public:
    DERendec();
    
    Ptr<Blob> EncodeStringDER(const Ptr<Blob> & str);
    
    Ptr<Blob> DecodeStringDER(const Ptr<Blob> blob, int & offset);

    Ptr<Blob> EncodeGTimeDER(const string & str);

    string DecodeGTimeDER(const Ptr<Blob> blob, int & offset);

    Ptr<Blob> EncodeOidDER(const string & str);

    string DecodeOidDER(const Ptr<Blob> blob, int & offset);

    Ptr<Blob> EncodeIntegerDER(const Ptr<Blob>);
    
    Ptr<Blob> DecodeIntegerDER(const Ptr<Blob> blob, int & offset);

    Ptr<Blob> EncodeBitStringDER(const Ptr<Blob> & bits, int paddingLen);

    Ptr<Blob> DecodeBitStringDER(const Ptr<Blob> blob, int & paddingLen, int & offset);

    Ptr<Blob> EncodeSequenceDER(vector<Ptr<Blob> > & components);

    Ptr<vector<Ptr<Blob> > > DecodeSequenceDER(const Ptr<Blob> blob, int & offset);

    Ptr<Blob> EncodeBoolDER(bool b);

    bool DecodeBoolDER(Ptr<Blob> blob, int & offset);

    Ptr<Blob> EncodeNULLDER();

    Ptr<Blob> EncodePrintableStringDER(const string & str);
    
    Ptr<string> DecodePrintableStringDER(const Ptr<Blob> blob, int & offset);
    
    void DecodeNULLDER(Ptr<Blob> blob, int & offset);

    void PrintDecoded(const Ptr<Blob> blob, string indent, int offset);

    void PrintBlob(const Ptr<Blob> blob, string indent);

    Ptr<vector<int> > StringToOid(const string & str);

    string OidToString(vector<int> & oid);
			 
  private:
    Ptr<Blob> EncodeSize(int size);

    int DecodeSize(const Ptr<Blob> blob, int & offset);

    Ptr<Blob> EncodeString(const Ptr<Blob> & str, int type);

    Ptr<Blob> EncodeInteger128(int i);

    int DecodeInteger128(const Ptr<Blob> blob, int & offset);

    Ptr<Blob> EncodeInteger32bDER(int32_t i);

  private:
    bool m_littleEndian;
  };

}//security

}//ndn

#endif

