/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "wire-ndnb-data.h"
#include "wire-ndnb.h"

#include "ndn.cxx/fields/signature-sha256-with-rsa.h"
#include "ndn.cxx/fields/key-locator.h"

#include "ndnb-parser/syntax-tree/block.h"
#include "ndnb-parser/syntax-tree/dtag.h"
#include "ndnb-parser/syntax-tree/blob.h"

#include "ndnb-parser/visitors/name-visitor.h"
#include "ndnb-parser/visitors/timestamp-visitor.h"
#include "ndnb-parser/visitors/content-type-visitor.h"


#include <boost/foreach.hpp>
#include <boost/iostreams/stream.hpp>

#include "logging.h"

INIT_LOGGER ("ndn.wire.Ndnb.Data");

NDN_NAMESPACE_BEGIN

namespace wire {
namespace ndnb {

  void 
  Data::SerializeUnsigned (const ndn::Data &data, OutputIterator &start)
  {
    Ptr<const Signature> sig = data.getSignature();

    // _LOG_DEBUG("Convert Signature!");

    Ptr<const signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<const signature::Sha256WithRsa>(sig);

    // _LOG_DEBUG("Append Name!");
    {
      Ndnb::AppendBlockHeader(start, NdnbParser::NDN_DTAG_Name, NdnbParser::NDN_DTAG); // <Name>
      Ndnb::SerializeName(start, data.getName());                // <Component>...</Component>...
      Ndnb::AppendCloser(start);                               // </Name>
    }

    // _LOG_DEBUG("Append SignedInfo!");
    {
      Ndnb::AppendBlockHeader(start, NdnbParser::NDN_DTAG_SignedInfo, NdnbParser::NDN_DTAG); // <SignedInfo>
      {
        // _LOG_DEBUG("Append PublisherPublicKeyDigest!");
        Ndnb::AppendTaggedBlob(start, 
                               NdnbParser::NDN_DTAG_PublisherPublicKeyDigest,
                               reinterpret_cast<const uint8_t*>(sha256sig->getPublisherKeyDigest().buf()), 
                               sha256sig->getPublisherKeyDigest().size()); //<PublisherPublicKeyDigest>
      }
      {
        // _LOG_DEBUG("Append Timestamp!");
        Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Timestamp, NdnbParser::NDN_DTAG);            // <Timestamp>...
        TimeInterval ti = data.getContent().getTimestamp() - time::UNIX_EPOCH_TIME;
        Ndnb::AppendTimestampBlob (start, ti);
        Ndnb::AppendCloser (start); //</Timestamp>
      }
      {
        // _LOG_DEBUG("Append KeyLocator!");
        Ndnb::AppendBlockHeader(start, NdnbParser::NDN_DTAG_KeyLocator, NdnbParser::NDN_DTAG); // <KeyLocator>
        {
          Ndnb::AppendBlockHeader(start, NdnbParser::NDN_DTAG_KeyName, NdnbParser::NDN_DTAG);    // <KeyName>
          {
            Ndnb::AppendBlockHeader(start, NdnbParser::NDN_DTAG_Name, NdnbParser::NDN_DTAG);       // <Name>
            Ndnb::SerializeName(start, sha256sig->getKeyLocator().getKeyName());         //   <Component>...</Component>...
            Ndnb::AppendCloser(start);                                     // </Name>
          }
          Ndnb::AppendCloser(start);                                     // </KeyName>
        }
        Ndnb::AppendCloser(start);                                     // </KeyLocator>
      }                           
    Ndnb::AppendCloser(start); // </SignedInfo>
    }

    // _LOG_DEBUG("Append Content!");
    {
      Ndnb::AppendBlockHeader(start, NdnbParser::NDN_DTAG_Content, NdnbParser::NDN_DTAG); // <Content>
      uint32_t payloadSize = data.content().size();
      if (payloadSize > 0){
        Ndnb::AppendBlockHeader (start, payloadSize, NdnbParser::NDN_BLOB);
        start.Write(reinterpret_cast<const uint8_t*>(data.content().buf()), data.content().size());
        // _LOG_DEBUG("payLoadSize: " << payloadSize);
      }

      Ndnb::AppendCloser(start); // </Content>
    }
  }

  void
  Data::Serialize (const ndn::Data &data, OutputIterator &start)
  {
    // _LOG_DEBUG("in Serialize");

    Ptr<const Signature> sig = data.getSignature();

    // _LOG_DEBUG("convert signature");

    Ptr<const signature::Sha256WithRsa> sha256sig = DynamicCast<const signature::Sha256WithRsa>(sig);

    // _LOG_DEBUG("Append Signature!");
    Ndnb::AppendBlockHeader(start, NdnbParser::NDN_DTAG_Data, NdnbParser::NDN_DTAG); // <Data>
    {
      Ndnb::AppendBlockHeader(start, NdnbParser::NDN_DTAG_Signature, NdnbParser::NDN_DTAG); //<Signature>
      {
        // Ndnb::AppendString(start, NdnbParser::NDN_DTAG_DigestAlgorithm, sha256sig->getDigestAlgorithm()); //<DigestAlgorithm>
        Ndnb::AppendTaggedBlobWithPadding(start, 
                                          NdnbParser::NDN_DTAG_SignatureBits, 
                                          16, 
                                          reinterpret_cast<const uint8_t*>(sha256sig->getSignatureBits().buf()), 
                                          sha256sig->getSignatureBits().size()); //<SignatureBits>
      }
      Ndnb::AppendCloser(start); //</Signature>
    }
    
    if(data.getSignedBlob() == NULL)
      SerializeUnsigned (data, start);
    else
      start.Write(reinterpret_cast<const unsigned char*>(data.getSignedBlob()->signed_buf()), data.getSignedBlob()->signed_size());
    
    Ndnb::AppendCloser(start);// </Data>
  }

  class DataVisitor : public NdnbParser::VoidDepthFirstVisitor
  {
  public:
    virtual void visit (NdnbParser::Dtag &n, boost::any param);
  };
    
  void
  DataVisitor::visit (NdnbParser::Dtag &n, boost::any param)
  {
    static NdnbParser::NameVisitor nameVisitor;
    static NdnbParser::TimestampVisitor timestampVisitor;
    static NdnbParser::ContentTypeVisitor contentTypeVisitor;

    ndn::Data *m_data = boost::any_cast<ndn::Data*> (param);

    switch (n.m_dtag)
    {
    case NdnbParser::NDN_DTAG_Data:
      // _LOG_DEBUG ("Data");
      BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case NdnbParser::NDN_DTAG_Signature:
      // _LOG_DEBUG ("Signature");
      BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case NdnbParser::NDN_DTAG_DigestAlgorithm:
      // _LOG_DEBUG ("DigestAlgorithm");
      break;
    case NdnbParser::NDN_DTAG_Witness:
      // _LOG_DEBUG ("Witness");
      break;
    case NdnbParser::NDN_DTAG_SignatureBits:
      {
        // _LOG_DEBUG ("SignatureBits");
        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
           throw NdnbParser::NdnbDecodingException ();

        Ptr<signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<signature::Sha256WithRsa>(m_data->getSignature ());
        Ptr<NdnbParser::Blob> sigBitsPtr = boost::dynamic_pointer_cast<NdnbParser::Blob>(*n.m_nestedTags.begin());
        sha256sig->setSignatureBits(Blob(sigBitsPtr->m_blob, sigBitsPtr->m_blobSize));

        break;
      }
    case NdnbParser::NDN_DTAG_Name:
      {
        // _LOG_DEBUG ("Name");

        // process name components
        Name name;
        n.accept (nameVisitor, &name);
        m_data->setName (name);
        break;
      }
    case NdnbParser::NDN_DTAG_SignedInfo:
      // _LOG_DEBUG ("SignedInfo");
      BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case NdnbParser::NDN_DTAG_PublisherPublicKeyDigest:
      {
        // _LOG_DEBUG ("PublisherPublicKeyDigest");
        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
          throw NdnbParser::NdnbDecodingException ();
        
        Ptr<signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<signature::Sha256WithRsa>(m_data->getSignature ());
        Ptr<NdnbParser::Blob> pubKeyDigest = boost::dynamic_pointer_cast<NdnbParser::Blob>(*n.m_nestedTags.begin());
        sha256sig->setPublisherKeyDigest(Blob(pubKeyDigest->m_blob, pubKeyDigest->m_blobSize));
        
        break;
      }
    case NdnbParser::NDN_DTAG_Timestamp:
      {
        // _LOG_DEBUG ("Timestamp");
        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
          throw NdnbParser::NdnbDecodingException ();

        TimeInterval tsOffset = boost::any_cast<TimeInterval> ((*n.m_nestedTags.begin())->accept(timestampVisitor));
        m_data->getContent().setTimeStamp(time::UNIX_EPOCH_TIME + tsOffset);
        break;
      }
    case NdnbParser::NDN_DTAG_Type:
      {
        // _LOG_DEBUG ("Type");
        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
          throw NdnbParser::NdnbDecodingException ();

        uint32_t typeBytes = boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept(contentTypeVisitor));
        m_data->getContent().setType(Data::toType(typeBytes));
        break;
      }
    case NdnbParser::NDN_DTAG_FreshnessSeconds:
      // _LOG_DEBUG ("FreshnessSeconds");
      m_data->getContent().setFreshness();
      break;
    case NdnbParser::NDN_DTAG_FinalBlockID:
      // _LOG_DEBUG ("NDN_DTAG_FinalBlockID");
      break;
    case NdnbParser::NDN_DTAG_KeyLocator:
      // _LOG_DEBUG ("KeyLocator");
      BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case NdnbParser::NDN_DTAG_KeyName:
      {
        // _LOG_DEBUG ("KeyName");
        
        // process name components
        Name name;
        n.accept (nameVisitor, &name);
        Ptr<signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<signature::Sha256WithRsa>(m_data->getSignature ());
        sha256sig->getKeyLocator().setType(ndn::KeyLocator::KEYNAME);
        sha256sig->getKeyLocator().setKeyName(name);
        break;
      }
    case NdnbParser::NDN_DTAG_Content:
      {
        // _LOG_DEBUG ("Content");

        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
          throw NdnbParser::NdnbDecodingException ();
        
        Ptr<NdnbParser::Blob> contentBlob = boost::dynamic_pointer_cast<NdnbParser::Blob>(*n.m_nestedTags.begin());
        m_data->getContent().setContent(Blob(contentBlob->m_blob, contentBlob->m_blobSize));
        break;
      }
    }
    
  }

  ndn::Content::Type
  Data::toType(uint32_t typeBytes)
  {
    switch(typeBytes){
    case 0x0C04C0:
      return ndn::Content::DATA;
    case 0x10D091:
      return ndn::Content::ENCR;
    case 0x18E344:
      return ndn::Content::GONE;
    case 0x28463F:
      return ndn::Content::KEY;
    case 0x2C834A:
      return ndn::Content::LINK;
    case 0x34008A:
      return ndn::Content::NACK;
    default:
      throw NdnbParser::NdnbDecodingException ();
    }
  }


  void
  Data::Deserialize (Ptr<ndn::Data> data, InputIterator &start)
  {
    static DataVisitor dataVisitor;

    Ptr<NdnbParser::Block> root = NdnbParser::Block::ParseBlock (start);
    root->accept (dataVisitor, GetPointer (data));
  }

} //ndnb
} //wire

NDN_NAMESPACE_END

// #include "../ndnb.h"

// #include "wire-ndnb.h"

// #include "ns3/log.h"

// #include "ndnb-parser/common.h"
// #include "ndnb-parser/visitors/void-depth-first-visitor.h"
// #include "ndnb-parser/visitors/name-visitor.h"
// #include "ndnb-parser/visitors/non-negative-integer-visitor.h"
// #include "ndnb-parser/visitors/timestamp-visitor.h"
// #include "ndnb-parser/visitors/string-visitor.h"
// #include "ndnb-parser/visitors/uint32t-blob-visitor.h"
// #include "ndnb-parser/visitors/content-type-visitor.h"

// #include "ndnb-parser/syntax-tree/block.h"
// #include "ndnb-parser/syntax-tree/dtag.h"

// #include <boost/foreach.hpp>

// NS_LOG_COMPONENT_DEFINE ("ndn.wire.Ndnb.Data");

// NDN_NAMESPACE_BEGIN

// namespace wire {
// namespace ndnb {

// // const std::string DefaultDigestAlgorithm = "2.16.840.1.101.3.4.2.1";

// class DataTrailer : public Trailer
// {
// public:
//   DataTrailer ()
//   {
//   }

//   static TypeId GetTypeId ()
//   {
//     static TypeId tid = TypeId ("ns3::ndn::Data::Ndnb::Closer")
//       .SetGroupName ("Ndn")
//       .SetParent<Trailer> ()
//       .AddConstructor<DataTrailer> ()
//       ;
//     return tid;
//   }

//   virtual TypeId GetInstanceTypeId (void) const
//   {
//     return GetTypeId ();
//   }

//   virtual void Print (std::ostream &os) const
//   {
//   }

//   virtual uint32_t GetSerializedSize (void) const
//   {
//     return 2;
//   }

//   virtual void Serialize (OutputIterator end) const
//   {
//     OutputIterator i = end;
//     i.Prev (2); // Trailer interface requires us to go backwards

//     i.WriteU8 (0x00); // </Content>
//     i.WriteU8 (0x00); // </Data>
//   }

//   virtual uint32_t Deserialize (InputIterator end)
//   {
//     InputIterator i = end;
//     i.Prev (2); // Trailer interface requires us to go backwards

//     uint8_t closing_tag_content = i.ReadU8 ();
//     NS_ASSERT_MSG (closing_tag_content==0, "Should be a closing tag </Content> (0x00)");

//     uint8_t closing_tag_content_object = i.ReadU8 ();
//     NS_ASSERT_MSG (closing_tag_content_object==0, "Should be a closing tag </Data> (0x00)");

//     return 2;
//   }
// };

// NS_OBJECT_ENSURE_REGISTERED (Data);
// NS_OBJECT_ENSURE_REGISTERED (DataTrailer);

// TypeId
// Data::GetTypeId (void)
// {
//   static TypeId tid = TypeId ("ns3::ndn::Data::Ndnb")
//     .SetGroupName ("Ndn")
//     .SetParent<Header> ()
//     .AddConstructor<Data> ()
//     ;
//   return tid;
// }

// TypeId
// Data::GetInstanceTypeId (void) const
// {
//   return GetTypeId ();
// }

// Data::Data ()
//   : m_data (Create<ndn::Data> ())
// {
// }

// Data::Data (Ptr<ndn::Data> data)
//   : m_data (data)
// {
// }

// Ptr<ndn::Data>
// Data::GetData ()
// {
//   return m_data;
// }

// Ptr<Packet>
// Data::ToWire (Ptr<const ndn::Data> data)
// {
//   static DataTrailer trailer;

//   Ptr<const Packet> p = data->GetWire ();
//   if (!p)
//     {
//       Ptr<Packet> packet = Create<Packet> (*data->GetPayload ());
//       Data wireEncoding (ConstCast<ndn::Data> (data));
//       packet->AddHeader (wireEncoding);
//       packet->AddTrailer (trailer);
//       data->SetWire (packet);

//       p = packet;
//     }

//   return p->Copy ();
// }

// Ptr<ndn::Data>
// Data::FromWire (Ptr<Packet> packet)
// {
//   static DataTrailer trailer;

//   Ptr<ndn::Data> data = Create<ndn::Data> ();
//   data->SetWire (packet->Copy ());

//   Data wireEncoding (data);
//   packet->RemoveHeader (wireEncoding);
//   packet->RemoveTrailer (trailer);

//   data->SetPayload (packet);

//   return data;
// }

// void
// Data::Serialize (OutputIterator start) const
// {
//   Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Data, NdnbParser::NDN_DTAG); // <Data>

//   // fake signature
//   Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Signature, NdnbParser::NDN_DTAG); // <Signature>
//   // Signature ::= √DigestAlgorithm?
//   //               Witness?
//   //               √SignatureBits
//   // if (GetSignature ().GetDigestAlgorithm () != Signature::DefaultDigestAlgorithm)
//   //   {
//   //     Ndnb::AppendString (start, NdnbParser::NDN_DTAG_DigestAlgorithm, GetSignature ().GetDigestAlgorithm ());
//   //   }
//   Ndnb::AppendString (start, NdnbParser::NDN_DTAG_DigestAlgorithm, "NOP");
//   Ndnb::AppendTaggedBlobWithPadding (start, NdnbParser::NDN_DTAG_SignatureBits, 16, m_data->GetSignature ()); // <SignatureBits />
//   Ndnb::AppendCloser (start);                                    // </Signature>

//   Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Name, NdnbParser::NDN_DTAG);    // <Name>
//   Ndnb::SerializeName (start, m_data->GetName());                                      //   <Component>...</Component>...
//   Ndnb::AppendCloser (start);                                                          // </Name>

//   // fake signature
//   Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_SignedInfo, NdnbParser::NDN_DTAG); // <SignedInfo>
//   // SignedInfo ::= √PublisherPublicKeyDigest
//   //                √Timestamp
//   //                √Type?
//   //                √FreshnessSeconds?
//   //                FinalBlockID?
//   //                KeyLocator?
//   // Ndnb::AppendTaggedBlob (start, NdnbParser::NDN_DTAG_PublisherPublicKeyDigest,         // <PublisherPublicKeyDigest>...
//   //                         GetSignedInfo ().GetPublisherPublicKeyDigest ());

//   Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Timestamp, NdnbParser::NDN_DTAG);            // <Timestamp>...
//   Ndnb::AppendTimestampBlob (start, m_data->GetTimestamp ());
//   Ndnb::AppendCloser (start);

//   // if (GetSignedInfo ().GetContentType () != DATA)
//   //   {
//   //     uint8_t type[3];
//   //     type[0] = (GetSignedInfo ().GetContentType () >> 16) & 0xFF;
//   //     type[1] = (GetSignedInfo ().GetContentType () >> 8 ) & 0xFF;
//   //     type[2] = (GetSignedInfo ().GetContentType ()      ) & 0xFF;

//   //     Ndnb::AppendTaggedBlob (start, NDN_DTAG_Type, type, 3);
//   //   }
//   if (m_data->GetFreshness () > Seconds(0))
//     {
//       Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_FreshnessSeconds, NdnbParser::NDN_DTAG);
//       Ndnb::AppendNumber (start, m_data->GetFreshness ().ToInteger (Time::S));
//       Ndnb::AppendCloser (start);
//     }
//   if (m_data->GetKeyLocator () != 0)
//     {
//       Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_KeyLocator, NdnbParser::NDN_DTAG); // <KeyLocator>
//       {
//         Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_KeyName, NdnbParser::NDN_DTAG);    // <KeyName>
//         {
//           Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Name, NdnbParser::NDN_DTAG);       // <Name>
//           Ndnb::SerializeName (start, *m_data->GetKeyLocator ());         //   <Component>...</Component>...
//           Ndnb::AppendCloser (start);                                     // </Name>
//         }
//         Ndnb::AppendCloser (start);                                     // </KeyName>
//       }
//       Ndnb::AppendCloser (start);                                     // </KeyLocator>
//     }

//   Ndnb::AppendCloser (start);                                     // </SignedInfo>

//   Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Content, NdnbParser::NDN_DTAG); // <Content>

//   uint32_t payloadSize = m_data->GetPayload ()->GetSize ();
//   if (payloadSize > 0)
//     Ndnb::AppendBlockHeader (start, payloadSize, NdnbParser::NDN_BLOB);

//   // there are no closing tags !!!
//   // The closing tag is handled by DataTail
// }

// uint32_t
// Data::GetSerializedSize () const
// {
//   size_t written = 0;
//   written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_Data); // <Data>

//   // fake signature
//   written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_Signature); // <Signature>
//   // Signature ::= DigestAlgorithm?
//   //               Witness?
//   //               SignatureBits
//   // if (GetSignature ().GetDigestAlgorithm () != Signature::DefaultDigestAlgorithm)
//   //   {
//   //     written += Ndnb::EstimateString (NdnbParser::NDN_DTAG_DigestAlgorithm, GetSignature ().GetDigestAlgorithm ());
//   //   }
//   written += Ndnb::EstimateString (NdnbParser::NDN_DTAG_DigestAlgorithm, "NOP");
//   // "signature" will be always padded to 16 octets
//   written += Ndnb::EstimateTaggedBlob (NdnbParser::NDN_DTAG_SignatureBits, 16);      // <SignatureBits />
//   // written += Ndnb::EstimateTaggedBlob (NdnbParser::NDN_DTAG_SignatureBits, sizeof (m_data->GetSignature ()));      // <SignatureBits />
//   written += 1;                                    // </Signature>

//   written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_Name);    // <Name>
//   written += Ndnb::SerializedSizeName (m_data->GetName ()); //   <Component>...</Component>...
//   written += 1;                                  // </Name>

//   // fake signature
//   written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_SignedInfo); // <SignedInfo>
//   // SignedInfo ::= √PublisherPublicKeyDigest
//   //                √Timestamp
//   //                √Type?
//   //                √FreshnessSeconds?
//   //                FinalBlockID?
//   //                KeyLocator?

//   // written += Ndnb::EstimateTaggedBlob (NDN_DTAG_PublisherPublicKeyDigest,                          // <PublisherPublicKeyDigest>...
//   //                                      sizeof (GetSignedInfo ().GetPublisherPublicKeyDigest ()));

//   written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_Timestamp);                  // <Timestamp>...
//   written += Ndnb::EstimateTimestampBlob (m_data->GetTimestamp ());
//   written += 1;

//   // if (GetSignedInfo ().GetContentType () != DATA)
//   //   {
//   //     written += Ndnb::EstimateTaggedBlob (NdnbParser::NDN_DTAG_Type, 3);
//   //   }
//   if (m_data->GetFreshness () > Seconds(0))
//     {
//       written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_FreshnessSeconds);
//       written += Ndnb::EstimateNumber (m_data->GetFreshness ().ToInteger (Time::S));
//       written += 1;
//     }

//   if (m_data->GetKeyLocator () != 0)
//     {
//       written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_KeyLocator); // <KeyLocator>
//       {
//         written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_KeyName);    // <KeyName>
//         {
//           written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_Name);       // <Name>
//           written += Ndnb::SerializedSizeName (*m_data->GetKeyLocator ());        //   <Component>...</Component>...
//           written += 1;                                               // </Name>
//         }
//         written += 1;                                               // </KeyName>
//       }
//       written += 1;                                               // </KeyLocator>
//     }

//   written += 1; // </SignedInfo>

//   written += Ndnb::EstimateBlockHeader (NdnbParser::NDN_DTAG_Content); // <Content>

//   uint32_t payloadSize = m_data->GetPayload ()->GetSize ();
//   if (payloadSize > 0)
//     written += Ndnb::EstimateBlockHeader (payloadSize);

//   // there are no closing tags !!!
//   // The closing tag is handled by DataTail
//   return written;
// }

// class DataVisitor : public NdnbParser::VoidDepthFirstVisitor
// {
// public:
//   virtual void visit (NdnbParser::Dtag &n, boost::any param/*should be Data* */)
//   {
//     // uint32_t n.m_dtag;
//     // std::list< Ptr<NdnbParser::Block> > n.m_nestedBlocks;
//     static NdnbParser::NameVisitor nameVisitor;
//     static NdnbParser::NonNegativeIntegerVisitor nonNegativeIntegerVisitor;
//     static NdnbParser::TimestampVisitor          timestampVisitor;
//     static NdnbParser::StringVisitor      stringVisitor;
//     static NdnbParser::Uint32tBlobVisitor uint32tBlobVisitor;
//     static NdnbParser::ContentTypeVisitor contentTypeVisitor;

//     ndn::Data &contentObject = *(boost::any_cast<ndn::Data*> (param));

//     switch (n.m_dtag)
//       {
//       case NdnbParser::NDN_DTAG_Data:
//         // process nested blocks
//         BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
//           {
//             block->accept (*this, param);
//           }
//         break;
//       case NdnbParser::NDN_DTAG_Name:
//         {
//           // process name components
//           Ptr<Name> name = Create<Name> ();
//           n.accept (nameVisitor, GetPointer (name));
//           contentObject.SetName (name);
//           break;
//         }

//       case NdnbParser::NDN_DTAG_Signature:
//         // process nested blocks
//         BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
//           {
//             block->accept (*this, param);
//           }
//         break;

//       // case NDN_DTAG_DigestAlgorithm:
//       //   NS_LOG_DEBUG ("DigestAlgorithm");
//       //   if (n.m_nestedTags.size ()!=1) // should be exactly one UDATA inside this tag
//       //     throw NdnbParser::NdnbDecodingException ();

//       //   contentObject.GetSignature ().SetDigestAlgorithm
//       //     (boost::any_cast<std::string> ((*n.m_nestedTags.begin())->accept
//       //                                    (stringVisitor)));
//       //   break;

//       case NdnbParser::NDN_DTAG_SignatureBits:
//         NS_LOG_DEBUG ("SignatureBits");
//         if (n.m_nestedTags.size ()!=1) // should be only one nested tag
//           throw NdnbParser::NdnbDecodingException ();

//         contentObject.SetSignature
//           (boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept
//                                       (uint32tBlobVisitor)));
//         break;

//       case NdnbParser::NDN_DTAG_SignedInfo:
//         // process nested blocks
//         BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
//           {
//             block->accept (*this, param);
//           }
//         break;

//       // case NDN_DTAG_PublisherPublicKeyDigest:
//       //   NS_LOG_DEBUG ("PublisherPublicKeyDigest");
//       //   if (n.m_nestedTags.size ()!=1) // should be only one nested tag
//       //     throw NdnbParser::NdnbDecodingException ();

//       //   contentObject.GetSignedInfo ().SetPublisherPublicKeyDigest
//       //     (boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept
//       //                                 (uint32tBlobVisitor)));
//       //   break;

//       case NdnbParser::NDN_DTAG_Timestamp:
//         NS_LOG_DEBUG ("Timestamp");
//         if (n.m_nestedTags.size()!=1) // should be exactly one nested tag
//           throw NdnbParser::NdnbDecodingException ();

//         contentObject.SetTimestamp
//           (boost::any_cast<Time> ((*n.m_nestedTags.begin())->accept
//                                   (timestampVisitor)));
//         break;

//       // case NDN_DTAG_Type:
//       //   NS_LOG_DEBUG ("Type");
//       //   if (n.m_nestedTags.size ()!=1) // should be only one nested tag
//       //     throw NdnbParser::NdnbDecodingException ();

//       //   contentObject.GetSignedInfo ().SetContentType
//       //     (static_cast<Data::ContentType>
//       //      (boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept
//       //                                  (contentTypeVisitor))));
//       //   break;

//       case NdnbParser::NDN_DTAG_FreshnessSeconds:
//         NS_LOG_DEBUG ("FreshnessSeconds");

//         if (n.m_nestedTags.size()!=1) // should be exactly one nested tag
//           throw NdnbParser::NdnbDecodingException ();

//         contentObject.SetFreshness
//           (Seconds
//            (boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept
//                                        (nonNegativeIntegerVisitor))));
//         break;

//       case NdnbParser::NDN_DTAG_KeyLocator:
//         // process nested blocks
//         BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
//           {
//             block->accept (*this, param);
//           }
//         break;

//       case NdnbParser::NDN_DTAG_KeyName:
//         {
//           if (n.m_nestedTags.size ()!=1) // should be exactly one nested tag
//             throw NdnbParser::NdnbDecodingException ();

//           // process name components
//           Ptr<Name> name = Create<Name> ();
//           n.accept (nameVisitor, GetPointer (name));
//           contentObject.SetKeyLocator (name);
//           break;
//         }

//       case NdnbParser::NDN_DTAG_Content: // !!! HACK
//         // This hack was necessary for memory optimizations (i.e., content is virtual payload)
//         NS_ASSERT_MSG (n.m_nestedTags.size() == 0, "Parser should have stopped just after processing <Content> tag");
//         break;

//       default: // ignore all other stuff
//         break;
//       }
//   }
// };

// uint32_t
// Data::Deserialize (InputIterator start)
// {
//   static DataVisitor contentObjectVisitor;

//   InputIterator i = start;
//   Ptr<NdnbParser::Block> root = NdnbParser::Block::ParseBlock (i);
//   root->accept (contentObjectVisitor, GetPointer (m_data));

//   return i.GetDistanceFrom (start);
// }

// void
// Data::Print (std::ostream &os) const
// {
//   os << "D: " << m_data->GetName ();
//   // os << "<Data><Name>" << GetName () << "</Name><Content>";
// }

// } // ndnb
// } // wire

// NDN_NAMESPACE_END
