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
    
    Ptr<Blob> EncodeStringDER(const Blob & str);
    
    Ptr<Blob> DecodeStringDER(const Blob & blob);

    Ptr<Blob> EncodeGTimeDER(const string & str);

    string DecodeGTimeDER(const Blob & blob);

    Ptr<Blob> EncodeIntegerDER(const Blob & blob);
    
    Ptr<Blob> DecodeIntegerDER(const Blob & blob);

    Ptr<Blob> EncodeBitStringDER(const Blob & bits, int paddingLen);

    Ptr<Blob> DecodeBitStringDER(const Blob & blob, int & paddingLen);

    Ptr<Blob> EncodeSequenceDER(vector<Ptr<Blob> > & components);

    Ptr<vector<Ptr<Blob> > > DecodeSequenceDER(const Blob & blob);

    Ptr<Blob> EncodeBoolDER(bool b);

    bool DecodeBoolDER(const Blob & blob);

    Ptr<Blob> EncodeNULLDER();

    void DecodeNULLDER(const Blob & blob);

    Ptr<Blob> EncodePrintableStringDER(const string & str);
    
    Ptr<string> DecodePrintableStringDER(const Blob & blob);

    void PrintDecoded(const Blob & blob, string indent, int offset);

    void PrintBlob(const Blob & blob, string indent);

    Ptr<Blob> EncodeSize(int size);

    int DecodeSize(const Blob & blob, int & offset);
    
    Ptr<Blob> EncodeString(const Blob & str, int type);

    Ptr<Blob> EncodeInteger128(int i);

    int DecodeInteger128(const Blob & blob, int & offset);
			 
  private:


    Ptr<Blob> EncodeInteger32bDER(int32_t i);

  private:
    bool m_littleEndian;
  };

}//security

}//ndn

#endif

