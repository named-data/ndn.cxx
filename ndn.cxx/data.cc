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

  Data::Data ()
  {
  }

  Data::~Data ()
  {
  }

  Ptr<Blob>
  Data::encodeToWire ()
  {
    blob_stream blobStream;
  
    wire::ccnb::Data::Serialize (*this, reinterpret_cast<OutputIterator &> (blobStream));

    return blobStream.buf ();
  }

  void
  Data::encodeToWire (std::ostream &os)
  {
    wire::ccnb::Data::Serialize (*this, reinterpret_cast<OutputIterator &> (os));  
  }
  
  Ptr<ndn::Data>
  Data::decodeFromWire (Ptr<const Blob> buffer)
  {
    boost::iostreams::stream
      <boost::iostreams::array_source> is (buffer->buf (), buffer->size ());

    Ptr<ndn::Data> data = Create<ndn::Data> ();
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
