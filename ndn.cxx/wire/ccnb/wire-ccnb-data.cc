/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "wire-ccnb-data.h"
#include "wire-ccnb.h"

#include "ndn.cxx/fields/signature-sha256-with-rsa.h"
#include "ndn.cxx/fields/key-locator.h"

#include "ccnb-parser/syntax-tree/block.h"
#include "ccnb-parser/syntax-tree/dtag.h"
#include "ccnb-parser/syntax-tree/blob.h"

#include "ccnb-parser/visitors/name-visitor.h"
#include "ccnb-parser/visitors/timestamp-visitor.h"
#include "ccnb-parser/visitors/content-type-visitor.h"


#include <boost/foreach.hpp>
#include <boost/iostreams/stream.hpp>

#include "logging.h"

INIT_LOGGER ("ndn.wire.Ccnb.Data");

NDN_NAMESPACE_BEGIN

namespace wire {
namespace ccnb {

  void 
  Data::SerializeUnsigned (const ndn::Data &data, OutputIterator &start)
  {
    Ptr<const Signature> sig = data.getSignature();

    _LOG_DEBUG("Convert Signature!");

    Ptr<const signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<const signature::Sha256WithRsa>(sig);

    _LOG_DEBUG("Append Name!");
    {
      Ccnb::AppendBlockHeader(start, CcnbParser::CCN_DTAG_Name, CcnbParser::CCN_DTAG); // <Name>
      Ccnb::SerializeName(start, data.getName());                // <Component>...</Component>...
      Ccnb::AppendCloser(start);                               // </Name>
    }

    _LOG_DEBUG("Append SignedInfo!");
    {
      Ccnb::AppendBlockHeader(start, CcnbParser::CCN_DTAG_SignedInfo, CcnbParser::CCN_DTAG); // <SignedInfo>
      {
        _LOG_DEBUG("Append PublisherPublicKeyDigest!");
        Ccnb::AppendTaggedBlob(start, 
                               CcnbParser::CCN_DTAG_PublisherPublicKeyDigest,
                               reinterpret_cast<const uint8_t*>(sha256sig->getPublisherKeyDigest().buf()), 
                               sha256sig->getPublisherKeyDigest().size()); //<PublisherPublicKeyDigest>
      }
      {
        _LOG_DEBUG("Append Timestamp!");
        Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_Timestamp, CcnbParser::CCN_DTAG);            // <Timestamp>...
        TimeInterval ti = data.getContent().getTimestamp() - time::UNIX_EPOCH_TIME;
        Ccnb::AppendTimestampBlob (start, ti);
        Ccnb::AppendCloser (start); //</Timestamp>
      }
      {
        _LOG_DEBUG("Append KeyLocator!");
        Ccnb::AppendBlockHeader(start, CcnbParser::CCN_DTAG_KeyLocator, CcnbParser::CCN_DTAG); // <KeyLocator>
        {
          Ccnb::AppendBlockHeader(start, CcnbParser::CCN_DTAG_KeyName, CcnbParser::CCN_DTAG);    // <KeyName>
          {
            Ccnb::AppendBlockHeader(start, CcnbParser::CCN_DTAG_Name, CcnbParser::CCN_DTAG);       // <Name>
            Ccnb::SerializeName(start, sha256sig->getKeyLocator().getKeyName());         //   <Component>...</Component>...
            Ccnb::AppendCloser(start);                                     // </Name>
          }
          Ccnb::AppendCloser(start);                                     // </KeyName>
        }
        Ccnb::AppendCloser(start);                                     // </KeyLocator>
      }                           
    Ccnb::AppendCloser(start); // </SignedInfo>
    }

    _LOG_DEBUG("Append Content!");
    {
      Ccnb::AppendBlockHeader(start, CcnbParser::CCN_DTAG_Content, CcnbParser::CCN_DTAG); // <Content>
      uint32_t payloadSize = data.content().size();
      if (payloadSize > 0){
        Ccnb::AppendBlockHeader (start, payloadSize, CcnbParser::CCN_BLOB);
        start.Write(reinterpret_cast<const uint8_t*>(data.content().buf()), data.content().size());
        _LOG_DEBUG("payLoadSize: " << payloadSize);
      }

      Ccnb::AppendCloser(start); // </Content>
    }
  }

  void
  Data::Serialize (const ndn::Data &data, OutputIterator &start)
  {
    _LOG_DEBUG("in Serialize");

    Ptr<const Signature> sig = data.getSignature();

    _LOG_DEBUG("convert signature");

    Ptr<const signature::Sha256WithRsa> sha256sig = DynamicCast<const signature::Sha256WithRsa>(sig);

    _LOG_DEBUG("Append Signature!");
    Ccnb::AppendBlockHeader(start, CcnbParser::CCN_DTAG_Data, CcnbParser::CCN_DTAG); // <Data>
    {
      Ccnb::AppendBlockHeader(start, CcnbParser::CCN_DTAG_Signature, CcnbParser::CCN_DTAG); //<Signature>
      {
        Ccnb::AppendString(start, CcnbParser::CCN_DTAG_DigestAlgorithm, sha256sig->getDigestAlgorithm()); //<DigestAlgorithm>
        Ccnb::AppendTaggedBlobWithPadding(start, 
                                          CcnbParser::CCN_DTAG_SignatureBits, 
                                          16, 
                                          reinterpret_cast<const uint8_t*>(sha256sig->getSignatureBits().buf()), 
                                          sha256sig->getSignatureBits().size()); //<SignatureBits>
      }
      Ccnb::AppendCloser(start); //</Signature>
    }
    
    SerializeUnsigned(data, start);
    
    Ccnb::AppendCloser(start);// </Data>
  }

  class DataVisitor : public CcnbParser::VoidDepthFirstVisitor
  {
  public:
    virtual void visit (CcnbParser::Dtag &n, boost::any param);
  };
    
  void
  DataVisitor::visit (CcnbParser::Dtag &n, boost::any param)
  {
    static CcnbParser::NameVisitor nameVisitor;
    static CcnbParser::TimestampVisitor timestampVisitor;
    static CcnbParser::ContentTypeVisitor contentTypeVisitor;

    ndn::Data *m_data = boost::any_cast<ndn::Data*> (param);

    switch (n.m_dtag)
    {
    case CcnbParser::CCN_DTAG_Data:
      _LOG_DEBUG ("Data");
      BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case CcnbParser::CCN_DTAG_Signature:
      _LOG_DEBUG ("Signature");
      BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case CcnbParser::CCN_DTAG_DigestAlgorithm:
      _LOG_DEBUG ("DigestAlgorithm");
      break;
    case CcnbParser::CCN_DTAG_Witness:
      _LOG_DEBUG ("Witness");
      break;
    case CcnbParser::CCN_DTAG_SignatureBits:
      {
        _LOG_DEBUG ("SignatureBits");
        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
           throw CcnbParser::CcnbDecodingException ();

        Ptr<signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<signature::Sha256WithRsa>(m_data->getSignature ());
        Ptr<CcnbParser::Blob> sigBitsPtr = boost::dynamic_pointer_cast<CcnbParser::Blob>(*n.m_nestedTags.begin());
        sha256sig->setSignatureBits(Blob(sigBitsPtr->m_blob, sigBitsPtr->m_blobSize));

        break;
      }
    case CcnbParser::CCN_DTAG_Name:
      {
        _LOG_DEBUG ("Name");

        // process name components
        Name name;
        n.accept (nameVisitor, &name);
        m_data->setName (name);
        break;
      }
    case CcnbParser::CCN_DTAG_SignedInfo:
      _LOG_DEBUG ("SignedInfo");
      BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case CcnbParser::CCN_DTAG_PublisherPublicKeyDigest:
      {
        _LOG_DEBUG ("PublisherPublicKeyDigest");
        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
          throw CcnbParser::CcnbDecodingException ();
        
        Ptr<signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<signature::Sha256WithRsa>(m_data->getSignature ());
        Ptr<CcnbParser::Blob> pubKeyDigest = boost::dynamic_pointer_cast<CcnbParser::Blob>(*n.m_nestedTags.begin());
        sha256sig->setPublisherKeyDigest(Blob(pubKeyDigest->m_blob, pubKeyDigest->m_blobSize));
        
        break;
      }
    case CcnbParser::CCN_DTAG_Timestamp:
      {
        _LOG_DEBUG ("Timestamp");
        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
          throw CcnbParser::CcnbDecodingException ();

        TimeInterval tsOffset = boost::any_cast<TimeInterval> ((*n.m_nestedTags.begin())->accept(timestampVisitor));
        m_data->getContent().setTimeStamp(time::UNIX_EPOCH_TIME + tsOffset);
        break;
      }
    case CcnbParser::CCN_DTAG_Type:
      {
        _LOG_DEBUG ("Type");
        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
          throw CcnbParser::CcnbDecodingException ();

        uint32_t typeBytes = boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept(contentTypeVisitor));
        m_data->getContent().setType(Data::toType(typeBytes));
        break;
      }
    case CcnbParser::CCN_DTAG_FreshnessSeconds:
      _LOG_DEBUG ("FreshnessSeconds");
      m_data->getContent().setFreshness();
      break;
    case CcnbParser::CCN_DTAG_FinalBlockID:
      _LOG_DEBUG ("CCN_DTAG_FinalBlockID");
      break;
    case CcnbParser::CCN_DTAG_KeyLocator:
      _LOG_DEBUG ("KeyLocator");
      BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case CcnbParser::CCN_DTAG_KeyName:
      {
        _LOG_DEBUG ("KeyName");
        
        // process name components
        Name name;
        n.accept (nameVisitor, &name);
        Ptr<signature::Sha256WithRsa> sha256sig = boost::dynamic_pointer_cast<signature::Sha256WithRsa>(m_data->getSignature ());
        sha256sig->getKeyLocator().setType(ndn::KeyLocator::KEYNAME);
        sha256sig->getKeyLocator().setKeyName(name);
        break;
      }
    case CcnbParser::CCN_DTAG_Content:
      {
        _LOG_DEBUG ("Content");

        if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
          throw CcnbParser::CcnbDecodingException ();
        
        Ptr<CcnbParser::Blob> contentBlob = boost::dynamic_pointer_cast<CcnbParser::Blob>(*n.m_nestedTags.begin());
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
      throw CcnbParser::CcnbDecodingException ();
    }
  }


  void
  Data::Deserialize (Ptr<ndn::Data> data, InputIterator &start)
  {
    static DataVisitor dataVisitor;

    Ptr<CcnbParser::Block> root = CcnbParser::Block::ParseBlock (start);
    root->accept (dataVisitor, GetPointer (data));
  }

} //ccnb
} //wire

NDN_NAMESPACE_END

// #include "../ccnb.h"

// #include "wire-ccnb.h"

// #include "ns3/log.h"

// #include "ccnb-parser/common.h"
// #include "ccnb-parser/visitors/void-depth-first-visitor.h"
// #include "ccnb-parser/visitors/name-visitor.h"
// #include "ccnb-parser/visitors/non-negative-integer-visitor.h"
// #include "ccnb-parser/visitors/timestamp-visitor.h"
// #include "ccnb-parser/visitors/string-visitor.h"
// #include "ccnb-parser/visitors/uint32t-blob-visitor.h"
// #include "ccnb-parser/visitors/content-type-visitor.h"

// #include "ccnb-parser/syntax-tree/block.h"
// #include "ccnb-parser/syntax-tree/dtag.h"

// #include <boost/foreach.hpp>

// NS_LOG_COMPONENT_DEFINE ("ndn.wire.Ccnb.Data");

// NDN_NAMESPACE_BEGIN

// namespace wire {
// namespace ccnb {

// // const std::string DefaultDigestAlgorithm = "2.16.840.1.101.3.4.2.1";

// class DataTrailer : public Trailer
// {
// public:
//   DataTrailer ()
//   {
//   }

//   static TypeId GetTypeId ()
//   {
//     static TypeId tid = TypeId ("ns3::ndn::Data::Ccnb::Closer")
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
//   static TypeId tid = TypeId ("ns3::ndn::Data::Ccnb")
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
//   Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_Data, CcnbParser::CCN_DTAG); // <Data>

//   // fake signature
//   Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_Signature, CcnbParser::CCN_DTAG); // <Signature>
//   // Signature ::= √DigestAlgorithm?
//   //               Witness?
//   //               √SignatureBits
//   // if (GetSignature ().GetDigestAlgorithm () != Signature::DefaultDigestAlgorithm)
//   //   {
//   //     Ccnb::AppendString (start, CcnbParser::CCN_DTAG_DigestAlgorithm, GetSignature ().GetDigestAlgorithm ());
//   //   }
//   Ccnb::AppendString (start, CcnbParser::CCN_DTAG_DigestAlgorithm, "NOP");
//   Ccnb::AppendTaggedBlobWithPadding (start, CcnbParser::CCN_DTAG_SignatureBits, 16, m_data->GetSignature ()); // <SignatureBits />
//   Ccnb::AppendCloser (start);                                    // </Signature>

//   Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_Name, CcnbParser::CCN_DTAG);    // <Name>
//   Ccnb::SerializeName (start, m_data->GetName());                                      //   <Component>...</Component>...
//   Ccnb::AppendCloser (start);                                                          // </Name>

//   // fake signature
//   Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_SignedInfo, CcnbParser::CCN_DTAG); // <SignedInfo>
//   // SignedInfo ::= √PublisherPublicKeyDigest
//   //                √Timestamp
//   //                √Type?
//   //                √FreshnessSeconds?
//   //                FinalBlockID?
//   //                KeyLocator?
//   // Ccnb::AppendTaggedBlob (start, CcnbParser::CCN_DTAG_PublisherPublicKeyDigest,         // <PublisherPublicKeyDigest>...
//   //                         GetSignedInfo ().GetPublisherPublicKeyDigest ());

//   Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_Timestamp, CcnbParser::CCN_DTAG);            // <Timestamp>...
//   Ccnb::AppendTimestampBlob (start, m_data->GetTimestamp ());
//   Ccnb::AppendCloser (start);

//   // if (GetSignedInfo ().GetContentType () != DATA)
//   //   {
//   //     uint8_t type[3];
//   //     type[0] = (GetSignedInfo ().GetContentType () >> 16) & 0xFF;
//   //     type[1] = (GetSignedInfo ().GetContentType () >> 8 ) & 0xFF;
//   //     type[2] = (GetSignedInfo ().GetContentType ()      ) & 0xFF;

//   //     Ccnb::AppendTaggedBlob (start, CCN_DTAG_Type, type, 3);
//   //   }
//   if (m_data->GetFreshness () > Seconds(0))
//     {
//       Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_FreshnessSeconds, CcnbParser::CCN_DTAG);
//       Ccnb::AppendNumber (start, m_data->GetFreshness ().ToInteger (Time::S));
//       Ccnb::AppendCloser (start);
//     }
//   if (m_data->GetKeyLocator () != 0)
//     {
//       Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_KeyLocator, CcnbParser::CCN_DTAG); // <KeyLocator>
//       {
//         Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_KeyName, CcnbParser::CCN_DTAG);    // <KeyName>
//         {
//           Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_Name, CcnbParser::CCN_DTAG);       // <Name>
//           Ccnb::SerializeName (start, *m_data->GetKeyLocator ());         //   <Component>...</Component>...
//           Ccnb::AppendCloser (start);                                     // </Name>
//         }
//         Ccnb::AppendCloser (start);                                     // </KeyName>
//       }
//       Ccnb::AppendCloser (start);                                     // </KeyLocator>
//     }

//   Ccnb::AppendCloser (start);                                     // </SignedInfo>

//   Ccnb::AppendBlockHeader (start, CcnbParser::CCN_DTAG_Content, CcnbParser::CCN_DTAG); // <Content>

//   uint32_t payloadSize = m_data->GetPayload ()->GetSize ();
//   if (payloadSize > 0)
//     Ccnb::AppendBlockHeader (start, payloadSize, CcnbParser::CCN_BLOB);

//   // there are no closing tags !!!
//   // The closing tag is handled by DataTail
// }

// uint32_t
// Data::GetSerializedSize () const
// {
//   size_t written = 0;
//   written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_Data); // <Data>

//   // fake signature
//   written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_Signature); // <Signature>
//   // Signature ::= DigestAlgorithm?
//   //               Witness?
//   //               SignatureBits
//   // if (GetSignature ().GetDigestAlgorithm () != Signature::DefaultDigestAlgorithm)
//   //   {
//   //     written += Ccnb::EstimateString (CcnbParser::CCN_DTAG_DigestAlgorithm, GetSignature ().GetDigestAlgorithm ());
//   //   }
//   written += Ccnb::EstimateString (CcnbParser::CCN_DTAG_DigestAlgorithm, "NOP");
//   // "signature" will be always padded to 16 octets
//   written += Ccnb::EstimateTaggedBlob (CcnbParser::CCN_DTAG_SignatureBits, 16);      // <SignatureBits />
//   // written += Ccnb::EstimateTaggedBlob (CcnbParser::CCN_DTAG_SignatureBits, sizeof (m_data->GetSignature ()));      // <SignatureBits />
//   written += 1;                                    // </Signature>

//   written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_Name);    // <Name>
//   written += Ccnb::SerializedSizeName (m_data->GetName ()); //   <Component>...</Component>...
//   written += 1;                                  // </Name>

//   // fake signature
//   written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_SignedInfo); // <SignedInfo>
//   // SignedInfo ::= √PublisherPublicKeyDigest
//   //                √Timestamp
//   //                √Type?
//   //                √FreshnessSeconds?
//   //                FinalBlockID?
//   //                KeyLocator?

//   // written += Ccnb::EstimateTaggedBlob (CCN_DTAG_PublisherPublicKeyDigest,                          // <PublisherPublicKeyDigest>...
//   //                                      sizeof (GetSignedInfo ().GetPublisherPublicKeyDigest ()));

//   written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_Timestamp);                  // <Timestamp>...
//   written += Ccnb::EstimateTimestampBlob (m_data->GetTimestamp ());
//   written += 1;

//   // if (GetSignedInfo ().GetContentType () != DATA)
//   //   {
//   //     written += Ccnb::EstimateTaggedBlob (CcnbParser::CCN_DTAG_Type, 3);
//   //   }
//   if (m_data->GetFreshness () > Seconds(0))
//     {
//       written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_FreshnessSeconds);
//       written += Ccnb::EstimateNumber (m_data->GetFreshness ().ToInteger (Time::S));
//       written += 1;
//     }

//   if (m_data->GetKeyLocator () != 0)
//     {
//       written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_KeyLocator); // <KeyLocator>
//       {
//         written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_KeyName);    // <KeyName>
//         {
//           written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_Name);       // <Name>
//           written += Ccnb::SerializedSizeName (*m_data->GetKeyLocator ());        //   <Component>...</Component>...
//           written += 1;                                               // </Name>
//         }
//         written += 1;                                               // </KeyName>
//       }
//       written += 1;                                               // </KeyLocator>
//     }

//   written += 1; // </SignedInfo>

//   written += Ccnb::EstimateBlockHeader (CcnbParser::CCN_DTAG_Content); // <Content>

//   uint32_t payloadSize = m_data->GetPayload ()->GetSize ();
//   if (payloadSize > 0)
//     written += Ccnb::EstimateBlockHeader (payloadSize);

//   // there are no closing tags !!!
//   // The closing tag is handled by DataTail
//   return written;
// }

// class DataVisitor : public CcnbParser::VoidDepthFirstVisitor
// {
// public:
//   virtual void visit (CcnbParser::Dtag &n, boost::any param/*should be Data* */)
//   {
//     // uint32_t n.m_dtag;
//     // std::list< Ptr<CcnbParser::Block> > n.m_nestedBlocks;
//     static CcnbParser::NameVisitor nameVisitor;
//     static CcnbParser::NonNegativeIntegerVisitor nonNegativeIntegerVisitor;
//     static CcnbParser::TimestampVisitor          timestampVisitor;
//     static CcnbParser::StringVisitor      stringVisitor;
//     static CcnbParser::Uint32tBlobVisitor uint32tBlobVisitor;
//     static CcnbParser::ContentTypeVisitor contentTypeVisitor;

//     ndn::Data &contentObject = *(boost::any_cast<ndn::Data*> (param));

//     switch (n.m_dtag)
//       {
//       case CcnbParser::CCN_DTAG_Data:
//         // process nested blocks
//         BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
//           {
//             block->accept (*this, param);
//           }
//         break;
//       case CcnbParser::CCN_DTAG_Name:
//         {
//           // process name components
//           Ptr<Name> name = Create<Name> ();
//           n.accept (nameVisitor, GetPointer (name));
//           contentObject.SetName (name);
//           break;
//         }

//       case CcnbParser::CCN_DTAG_Signature:
//         // process nested blocks
//         BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
//           {
//             block->accept (*this, param);
//           }
//         break;

//       // case CCN_DTAG_DigestAlgorithm:
//       //   NS_LOG_DEBUG ("DigestAlgorithm");
//       //   if (n.m_nestedTags.size ()!=1) // should be exactly one UDATA inside this tag
//       //     throw CcnbParser::CcnbDecodingException ();

//       //   contentObject.GetSignature ().SetDigestAlgorithm
//       //     (boost::any_cast<std::string> ((*n.m_nestedTags.begin())->accept
//       //                                    (stringVisitor)));
//       //   break;

//       case CcnbParser::CCN_DTAG_SignatureBits:
//         NS_LOG_DEBUG ("SignatureBits");
//         if (n.m_nestedTags.size ()!=1) // should be only one nested tag
//           throw CcnbParser::CcnbDecodingException ();

//         contentObject.SetSignature
//           (boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept
//                                       (uint32tBlobVisitor)));
//         break;

//       case CcnbParser::CCN_DTAG_SignedInfo:
//         // process nested blocks
//         BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
//           {
//             block->accept (*this, param);
//           }
//         break;

//       // case CCN_DTAG_PublisherPublicKeyDigest:
//       //   NS_LOG_DEBUG ("PublisherPublicKeyDigest");
//       //   if (n.m_nestedTags.size ()!=1) // should be only one nested tag
//       //     throw CcnbParser::CcnbDecodingException ();

//       //   contentObject.GetSignedInfo ().SetPublisherPublicKeyDigest
//       //     (boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept
//       //                                 (uint32tBlobVisitor)));
//       //   break;

//       case CcnbParser::CCN_DTAG_Timestamp:
//         NS_LOG_DEBUG ("Timestamp");
//         if (n.m_nestedTags.size()!=1) // should be exactly one nested tag
//           throw CcnbParser::CcnbDecodingException ();

//         contentObject.SetTimestamp
//           (boost::any_cast<Time> ((*n.m_nestedTags.begin())->accept
//                                   (timestampVisitor)));
//         break;

//       // case CCN_DTAG_Type:
//       //   NS_LOG_DEBUG ("Type");
//       //   if (n.m_nestedTags.size ()!=1) // should be only one nested tag
//       //     throw CcnbParser::CcnbDecodingException ();

//       //   contentObject.GetSignedInfo ().SetContentType
//       //     (static_cast<Data::ContentType>
//       //      (boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept
//       //                                  (contentTypeVisitor))));
//       //   break;

//       case CcnbParser::CCN_DTAG_FreshnessSeconds:
//         NS_LOG_DEBUG ("FreshnessSeconds");

//         if (n.m_nestedTags.size()!=1) // should be exactly one nested tag
//           throw CcnbParser::CcnbDecodingException ();

//         contentObject.SetFreshness
//           (Seconds
//            (boost::any_cast<uint32_t> ((*n.m_nestedTags.begin())->accept
//                                        (nonNegativeIntegerVisitor))));
//         break;

//       case CcnbParser::CCN_DTAG_KeyLocator:
//         // process nested blocks
//         BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
//           {
//             block->accept (*this, param);
//           }
//         break;

//       case CcnbParser::CCN_DTAG_KeyName:
//         {
//           if (n.m_nestedTags.size ()!=1) // should be exactly one nested tag
//             throw CcnbParser::CcnbDecodingException ();

//           // process name components
//           Ptr<Name> name = Create<Name> ();
//           n.accept (nameVisitor, GetPointer (name));
//           contentObject.SetKeyLocator (name);
//           break;
//         }

//       case CcnbParser::CCN_DTAG_Content: // !!! HACK
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
//   Ptr<CcnbParser::Block> root = CcnbParser::Block::ParseBlock (i);
//   root->accept (contentObjectVisitor, GetPointer (m_data));

//   return i.GetDistanceFrom (start);
// }

// void
// Data::Print (std::ostream &os) const
// {
//   os << "D: " << m_data->GetName ();
//   // os << "<Data><Name>" << GetName () << "</Name><Content>";
// }

// } // ccnb
// } // wire

// NDN_NAMESPACE_END
