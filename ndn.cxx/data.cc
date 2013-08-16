/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "data.h"

#include "wire/ccnb/wire-ccnb-data.h"

#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

#include "logging.h"

INIT_LOGGER ("ndn.Data");

namespace ndn {
  const int MAGIC_SIGNED_BLOB_OFFSET = 2 + (2 + (2 + (2 + 22) + 1) + (2 + (2 + 256) + 1) + 1);
  const int LAST_CLOSER_SIZE = 1;

  Data::Data ()
  {
  }

  Data::~Data ()
  {
  }

  Ptr<Blob>
  Data::encodeToUnsignedWire () const
  {
    blob_stream blobStream;
  
    wire::ccnb::Data::SerializeUnsigned (*this, reinterpret_cast<OutputIterator &> (blobStream));

    return blobStream.buf ();
  }

    void
  Data::encodeToUnsignedWire (std::ostream &os) const
  {
    wire::ccnb::Data::SerializeUnsigned (*this, reinterpret_cast<OutputIterator &> (os));  
  }

  Ptr<Blob>
  Data::encodeToWire () const
  {
    blob_stream blobStream;
  
    wire::ccnb::Data::Serialize (*this, reinterpret_cast<OutputIterator &> (blobStream));

    return blobStream.buf ();
  }

  void
  Data::encodeToWire (std::ostream &os) const
  {
    wire::ccnb::Data::Serialize (*this, reinterpret_cast<OutputIterator &> (os));  
  }
  
  Ptr<ndn::Data>
  Data::decodeFromWire (Ptr<const Blob> buffer)
  {
    boost::iostreams::stream
      <boost::iostreams::array_source> is (buffer->buf (), buffer->size ());

    Ptr<ndn::Data> data = Create<ndn::Data> ();
    
    Ptr<SignedBlob> signedBlob = Ptr<SignedBlob>(new SignedBlob(buffer->buf (), buffer->size ()));

    signedBlob->setSignedPortion(MAGIC_SIGNED_BLOB_OFFSET, buffer->size() - MAGIC_SIGNED_BLOB_OFFSET - LAST_CLOSER_SIZE);

    data->setSignedBlob(signedBlob);

    data->setSignature(Create<signature::Sha256WithRsa> ());

    wire::ccnb::Data::Deserialize (data, reinterpret_cast<InputIterator &> (is)); // crazy, but safe

    return data;
  }
  
  Ptr<ndn::Data>
  Data::decodeFromWire (std::istream &is)
  {

    Ptr<ndn::Data> data = Create<ndn::Data> ();
    data->setSignature(Create<signature::Sha256WithRsa> ());

    wire::ccnb::Data::Deserialize (data, reinterpret_cast<InputIterator &> (is)); // crazy, but safe

    return data;
  }

} // namespace ndn
