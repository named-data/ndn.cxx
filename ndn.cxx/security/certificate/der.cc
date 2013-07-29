/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <stdlib.h>
#include <sstream>

#include "der.h"
#include "ndn.cxx/security/exception.h"

#include "logging.h"

INIT_LOGGER ("OSXPrivateKeyStore");

using namespace std;

namespace ndn
{

namespace security
{
  DERendec::DERendec()
  {
    uint32_t i = 1;
    m_littleEndian = (1 == *(char *)&i);
  }

  Ptr<Blob> DERendec::EncodeStringDER(const Blob & str)
  {
    return EncodeString(str, 0x04);
  }

  Ptr<Blob> DERendec::DecodeStringDER(const Blob & blob)
  {
    if(0x04 != blob[0])
      throw SecException("Decode Octet String, Type mismatch");

    int offset = 1;

    int size = DecodeSize(blob, offset);
    
    Ptr<Blob> result = Ptr<Blob>::Create();
    result->insert(result->end(), blob.begin() + offset , blob.begin() + offset + size);

    return result;
  }

  Ptr<Blob> DERendec::EncodePrintableStringDER(const string & str)
  {
    return EncodeString(Blob(str.c_str(), str.size()), 0x13);
  }
    
  Ptr<string> DERendec::DecodePrintableStringDER(const Blob & blob)
  {
    int offset = 0;

    if(0x13 != blob[offset])
      throw SecException("Decode Printable String, Type mismatch");

    offset++;

    int size = DecodeSize(blob, offset);

    return Ptr<string>(new string(blob.begin() + offset, blob.begin() + offset + size));
  }


  Ptr<Blob> DERendec::EncodeSize(int size)
  {
    Ptr<Blob> result = Ptr<Blob>::Create();
    if(size >= 127){
      int numerator = size;
      int reminder = 0;

      Ptr<Blob> lenBytes = Ptr<Blob>::Create();
    
      while(numerator > 0){
	reminder = numerator % 256;
	numerator = numerator / 256;
	lenBytes->push_back(static_cast<char>(reminder));
      }
    
      result->insert(result->end(), 1<<7 | static_cast<char>(lenBytes->size()));
      result->insert(result->end(), lenBytes->rbegin(), lenBytes->rend());
    }
    else{
      result->push_back(size);
    }

    return result;
  }

  int DERendec::DecodeSize(const Blob & blob, int & offset)
  {
    uint8_t flagMask = 0x80;

    if(0 == (blob[offset] & flagMask)){
      int len = blob[offset];
      offset ++;
      return len;
    }
    else{
      int len = 0;
      int numLen = (uint8_t) blob[offset] - flagMask;
      int i = 0;
      for(; i < numLen; i++){
	len = len * 256 + blob[offset + 1 + i];
      }
      offset = offset + 1 + numLen;
      return len;
    }
  }

  Ptr<Blob> DERendec::EncodeString(const Blob & str, int type)
  {
    Ptr<Blob> result = Ptr<Blob>::Create();
    result->push_back(type);

    int size = str.size();
    Ptr<Blob> lenBytes = EncodeSize(size);

    result->insert(result->end(), lenBytes->begin(), lenBytes->end());
    result->insert(result->end(), str.begin(), str.end());
    
    return result;
  }

  Ptr<Blob> DERendec::EncodeGTimeDER(const string & str)
  {
    return EncodeString(Blob(str.c_str(), str.size()), 0x18);
  }

  string DERendec::DecodeGTimeDER(const Blob & blob)
  {
    if(0x18 != blob[0])
      throw SecException("Decode GeneralizeTime, Type mismatch");

    int offset = 1;

    int size = DecodeSize(blob, offset);

    return string(blob.begin() + offset , blob.begin() + offset + size);
  }

  Ptr<Blob> DERendec::EncodeInteger128(int i)
  {
    Ptr<Blob> result =  Ptr<Blob>::Create();
    
    if(128 > i)
      result->push_back(i);
    else{
      int numerator = i;
      int reminder = 0;
      bool first = true;
      Ptr<Blob> tmpResult = Ptr<Blob>::Create();

      while(numerator > 0){
	reminder = numerator % 128;
	numerator = numerator / 128;
	if(false == first)
	  reminder = (1<<7 | reminder);
	if(true == first)
	  first = false;
	tmpResult->push_back(reminder);
      }

      result->insert(result->end(), tmpResult->rbegin(), tmpResult->rend());
    }

    return result;
  }

  int DERendec::DecodeInteger128(const Blob & blob, int & offset)
  {
    uint8_t flagMask = 0x80;
    int result = 0;
    while(blob[offset] & flagMask){
      result = 128 * result + (uint8_t) blob[offset] - 128;
      offset++;
    }

    result = result * 128 + blob[offset];
    offset++;

    return result;
  }

  Ptr<Blob> DERendec::EncodeInteger32bDER(int32_t i)
  {
    Ptr<Blob> result = Ptr<Blob>::Create();
    result->push_back(2);


    uint32_t longSignMask = 1 << 31;
    uint8_t byteMask = 0xFF;
    uint8_t signMask = 0x80;
    uint8_t refer = 0xFF;
    uint8_t sign = 0x00;
    
    int8_t ilen = sizeof(i); 
    uint8_t* p = (uint8_t*) & i;

    int8_t count = 0;
    
    if(m_littleEndian){
      if(0 == (i & longSignMask)){
	refer = 0x00;
	sign = 0x80;
      }

      bool found = false;
      int8_t index = ilen - 1;
      for(; index >=0; index--){
	if(refer != (byteMask & p[index])){
	  found = true;
	  break;
	}
      }
      if(found){
	if(sign == (signMask & p[index])){
	  index++;
	}
	result->push_back(index + 1);
	if(index >= ilen)
	  result->push_back(sign);
	for(; index >=0; index--){
	  result->push_back(p[index]);
	}
      }
      else{
	result->push_back(1);
	result->push_back(refer);
      }
      return result;
    }
    else{
      _LOG_DEBUG("big-endian not implemented");
      return NULL;
    }

  }

  Ptr<Blob> DERendec::EncodeIntegerDER(const Blob & blob)
  {
    Ptr<Blob> result = Ptr<Blob>::Create();
    result->push_back(0x02);

    Ptr<Blob> lenPtr = EncodeSize(blob.size());

    result->insert(result->end(), lenPtr->begin(), lenPtr->end());
    result->insert(result->end(), blob.begin(), blob.end());

    return result;
  }

  Ptr<Blob> DERendec::DecodeIntegerDER(const Blob & blob)
  {
    Ptr<Blob> result = Ptr<Blob>::Create();
    int offset = 0;
    if(0x02 != blob[offset])
      throw SecException("Decode Integer, Type mismatch");

    offset++;

    int size = DecodeSize(blob, offset);

    result->insert(result->end(), blob.begin() + offset, blob.begin() + offset + size);
    
    offset += size;

    return result;
  }

  Ptr<Blob> DERendec::EncodeSequenceDER(vector<Ptr<Blob> > & components)
  {
    Ptr<Blob> result = Ptr<Blob>::Create();

    result->push_back(0x30);

    vector<Ptr<Blob> >::iterator it = components.begin();
    int size = 0;
    for(; it < components.end(); it++)
      size += (*it)->size();

    Ptr<Blob> lenBytes = EncodeSize(size);

    result->insert(result->end(), lenBytes->begin(), lenBytes->end());

    it = components.begin();
    for(; it < components.end(); it++)
      result->insert(result->end(), (*it)->begin(), (*it)->end());

    return result;
  }

  Ptr<vector<Ptr<Blob> > > DERendec::DecodeSequenceDER(const Blob & blob)
  {
    Ptr<vector<Ptr<Blob> > > blobList = Ptr<vector<Ptr<Blob> > >::Create();
    int offset = 0;

    if(0x30 != blob[offset])
      throw SecException("Decode Sequence, Type mismatch");
    
    offset++;

    int size = DecodeSize(blob, offset);
    int end = offset + size;
    int tmpSize = 0;
    int begin = 0;
    
    while(offset < end){
      begin = offset;
      offset++;
 
      tmpSize = DecodeSize(blob, offset);
      
      Ptr<Blob> item = Ptr<Blob>::Create();      
      item->insert(item->end(), blob.begin() + begin, blob.end() + offset + tmpSize);
      blobList->push_back(item);
      
      offset += tmpSize;
    }
    
    return blobList;
  }

  Ptr<Blob> DERendec::EncodeBitStringDER(const Blob & bits, int paddingLen)
  {
    Ptr<Blob> result =  Ptr<Blob>::Create();
    
    result->push_back(0x03);

    Ptr<Blob> lenBytes = EncodeSize(bits.size()+1);
    result->insert(result->end(), lenBytes->begin(), lenBytes->end());

    result->push_back(paddingLen);

    result->insert(result->end(), bits.begin(), bits.end());
    
    return result;
  }

  Ptr<Blob> DERendec::DecodeBitStringDER(const Blob & blob, int & paddingLen)
  {
    int offset = 0;
    if(0x03 != blob[offset])
      throw SecException("Decode Bit String, Type mismatch");

    offset++;
    
    Ptr<Blob> result = Ptr<Blob>::Create();
    
    int size = DecodeSize(blob, offset);

    paddingLen = blob.at(offset);

    offset++;
    
    result->insert(result->end(), blob.begin() + offset, blob.begin() + offset + size);
    
    offset += size;

    return result;
  }

  Ptr<Blob> DERendec::EncodeBoolDER(bool b)
  {
    Ptr<Blob> result = Ptr<Blob>::Create();
    result->push_back(1);
    result->push_back(1);
    if(b)
      result->push_back(0);
    else
      result->push_back(0xFF);
    
    return result;
  }

  bool DERendec::DecodeBoolDER(const Blob & blob)
  {
    int offset = 0;

    if(0x01 != blob[offset])
      throw SecException("Decode Boolean, Type mismatch");
    offset++;

    if(0x01 != blob[offset])
      throw SecException("Decode Boolean, Wrong size");
    offset++;

    if(0 == blob[offset]){
      offset++;
      return false;
    }
    else{
      offset++;
      return true;
    }
  }

  Ptr<Blob> DERendec::EncodeNULLDER()
  {
    Ptr<Blob> result = Ptr<Blob>::Create();
    result->push_back(0x05);
    result->push_back(0x00);
    return result;
  }

  void DERendec::DecodeNULLDER(const Blob & blob)
  {
    int offset = 0;
    if(0x05 != blob[offset])
      throw SecException("Decode Boolean, Type mismatch");
    offset++;

    if(0x05 != blob[offset])
      throw SecException("Decode Boolean, Wrong size");
    offset++;
  }

  void DERendec::PrintBlob(const Blob & p, string indent)
  {
    Blob::const_iterator it = p.begin();
    cout << indent;
    int count = 0;
    for(; it < p.end(); it++){
      cout << " " << hex << setw(2) << setfill('0') << (unsigned int) ((unsigned char) *it);
      count++;
      if(8 == count){
	count = 0;
	cout << "\n" << indent;
      }
	
    }
    cout << endl;
  }

  void DERendec::PrintDecoded(const Blob & blob, string indent, int offset)
  {
    int begin = offset;
    cout << indent << hex << setw(2) << setfill('0') << (int)(uint8_t)blob[offset];

    offset++;
    int size = DecodeSize(blob, offset);

    Blob sizeBlob;
    sizeBlob.insert(sizeBlob.end(), blob.begin() + begin + 1, blob.begin() + offset);
    PrintBlob(sizeBlob, "");
    
    if(0x30 != blob[begin]){
      Blob dataBlob;
      dataBlob.insert(dataBlob.end(), blob.begin() + offset, blob.begin() + offset + size);
      if(0x03 == blob[begin]){
	cout << (indent + "   ") << hex << setw(2) << setfill('0') << (int)(uint8_t)dataBlob[0] << endl;
	dataBlob.erase(dataBlob.begin());
	PrintDecoded(dataBlob, indent + "   ", 0);
      }
      else
      PrintBlob(dataBlob, indent + " | ");      
    }
    else{
      Ptr<vector<Ptr<Blob> > > blobList = DecodeSequenceDER(blob);
      int i = 0;
      for(; i < blobList->size(); i++){
    	PrintDecoded(*blobList->at(i), indent + " | ", 0);
      }
    }
  }

  

}//security

}//ndn
