/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "wire-ndnb-interest.h"
#include "logging.h"

#include "wire-ndnb.h"


#include "ndnb-parser/visitors/name-visitor.h"
#include "ndnb-parser/visitors/non-negative-integer-visitor.h"
#include "ndnb-parser/visitors/timestamp-visitor.h"
#include "ndnb-parser/visitors/uint32t-blob-visitor.h"

#include "ndnb-parser/syntax-tree/block.h"
#include "ndnb-parser/syntax-tree/dtag.h"

#include <boost/foreach.hpp>
#include <boost/iostreams/stream.hpp>

INIT_LOGGER ("ndn.wire.Ndnb.Interest");

NDN_NAMESPACE_BEGIN

namespace wire {
namespace ndnb {

void
Interest::Serialize (const ndn::Interest &interest, OutputIterator &start)
{
  Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Interest, NdnbParser::NDN_DTAG); // <Interest>
  
  Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Name, NdnbParser::NDN_DTAG); // <Name>
  Ndnb::SerializeName (start, interest.getName());                // <Component>...</Component>...
  Ndnb::AppendCloser (start);                               // </Name>

  if (interest.getMinSuffixComponents () != ndn::Interest::ncomps)
    {
      Ndnb::AppendTaggedNumber (start, NdnbParser::NDN_DTAG_MinSuffixComponents, interest.getMinSuffixComponents ());
    }
  if (interest.getMaxSuffixComponents () != ndn::Interest::ncomps)
    {
      Ndnb::AppendTaggedNumber (start, NdnbParser::NDN_DTAG_MaxSuffixComponents, interest.getMaxSuffixComponents ());
    }
  // if (interest.getExclude ().size () > 0)
  //   {
  //     Ndnb::AppendExclude (start, interest.getExclude ());
  //   }
  if (interest.getChildSelector () != ndn::Interest::CHILD_DEFAULT)
    {
      Ndnb::AppendTaggedNumber (start, NdnbParser::NDN_DTAG_ChildSelector, interest.getChildSelector ());
    }
  if (interest.getAnswerOriginKind () != ndn::Interest::AOK_DEFAULT)
    {
      Ndnb::AppendTaggedNumber (start, NdnbParser::NDN_DTAG_AnswerOriginKind, interest.getAnswerOriginKind ());
    }
  if (interest.getScope () != ndn::Interest::NO_SCOPE)
    {
      Ndnb::AppendTaggedNumber (start, NdnbParser::NDN_DTAG_Scope, interest.getScope ());
    }
  if (!interest.getInterestLifetime ().is_negative ())
    {
      Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_InterestLifetime, NdnbParser::NDN_DTAG);
      Ndnb::AppendTimestampBlob (start, interest.getInterestLifetime ());
      Ndnb::AppendCloser (start);
    }
  // if (interest.GetNonce()>0)
  //   {
  //     uint32_t nonce = interest.getNonce();
  //     Ndnb::AppendTaggedBlob (start, NdnbParser::NDN_DTAG_Nonce, nonce);
  //   }
    
  // if (interest.GetNack ()>0)
  //   {
  //     Ndnb::AppendBlockHeader (start, NdnbParser::NDN_DTAG_Nack, NdnbParser::NDN_DTAG);
  //     Ndnb::AppendNumber (start, interest.GetNack ());
  //     Ndnb::AppendCloser (start);
  //   }
  Ndnb::AppendCloser (start); // </Interest>
}

class InterestVisitor : public NdnbParser::VoidDepthFirstVisitor
{
public:
  virtual void visit (NdnbParser::Dtag &n, boost::any param/*should be NdnxInterest* */);
};

// We don't care about any other fields
void
InterestVisitor::visit (NdnbParser::Dtag &n, boost::any param/*should be Interest* */)
{
  // uint32_t n.m_dtag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;

  static NdnbParser::NonNegativeIntegerVisitor nonNegativeIntegerVisitor;
  static NdnbParser::NameVisitor               nameVisitor;
  static NdnbParser::TimestampVisitor          timestampVisitor;
  static NdnbParser::Uint32tBlobVisitor        nonceVisitor;
  
  ndn::Interest *m_interest = boost::any_cast<ndn::Interest*> (param);

  switch (n.m_dtag)
    {
    case NdnbParser::NDN_DTAG_Interest:
      _LOG_DEBUG ("Interest");
  
      // process nested blocks
      BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case NdnbParser::NDN_DTAG_Name:
      {
        _LOG_DEBUG ("Name");

        // process name components
        Name name;
        n.accept (nameVisitor, &name);
        m_interest->setName (name);
        break;
      }
    // case NdnbParser::NDN_DTAG_MinSuffixComponents:
    //   _LOG_DEBUG ("MinSuffixComponents");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw NdnbParser::NdnbDecodingException ();
    //   m_interest->SetMinSuffixComponents (
    //            boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonNegativeIntegerVisitor
    //                                                                        )));
    //   break;
    // case NdnbParser::NDN_DTAG_MaxSuffixComponents:
    //   _LOG_DEBUG ("MaxSuffixComponents");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw NdnbParser::NdnbDecodingException ();
    //   m_interest->SetMaxSuffixComponents (
    //            boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonNegativeIntegerVisitor
    //                                                                        )));
    //   break;
    // case NdnbParser::NDN_DTAG_Exclude:
    //   {
    //     _LOG_DEBUG ("Exclude");
    //     // process exclude components
    //     Ptr<Name> exclude = Create<Name> ();
        
    //     BOOST_FOREACH (Ptr<NdnbParser::Block> block, n.m_nestedTags)
    //       {
    //         block->accept (nameVisitor, &(*exclude));
    //       }
    //     m_interest->SetExclude (exclude);
    //     break;
    //   }
    // case NdnbParser::NDN_DTAG_ChildSelector:
    //   _LOG_DEBUG ("ChildSelector");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw NdnbParser::NdnbDecodingException ();

    //   m_interest->SetChildSelector (
    //            1 == boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonNegativeIntegerVisitor
    //                                                                        )));
    //   break;
    // case NDN_DTAG_AnswerOriginKind:
    //   _LOG_DEBUG ("AnswerOriginKind");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw NdnbParser::NdnbDecodingException ();
    //   m_interest->SetAnswerOriginKind (
    //            1 == boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonNegativeIntegerVisitor
    //                                                                        )));
    //   break;
    case NdnbParser::NDN_DTAG_Scope: 
      _LOG_DEBUG ("Scope");
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw NdnbParser::NdnbDecodingException ();
      m_interest->setScope (
               boost::any_cast<uint32_t> (
                                          (*n.m_nestedTags.begin())->accept(
                                                                           nonNegativeIntegerVisitor
                                                                           )));
      break;
    case NdnbParser::NDN_DTAG_InterestLifetime:
      _LOG_DEBUG ("InterestLifetime");
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw NdnbParser::NdnbDecodingException ();

      m_interest->setInterestLifetime (
               boost::any_cast<TimeInterval> (
                                      (*n.m_nestedTags.begin())->accept(
                                                                        timestampVisitor
                                                                        )));
      break;
    // case NdnbParser::NDN_DTAG_Nonce:
    //   _LOG_DEBUG ("Nonce");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw NdnbParser::NdnbDecodingException ();

    //   m_interest->SetNonce (
    //            boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonceVisitor
    //                                                                        )));
    //   break;
    
            
    // case NdnbParser::NDN_DTAG_Nack:
    //   _LOG_DEBUG ("Nack");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw NdnbParser::NdnbDecodingException ();
            
    //   m_interest->SetNack (
    //            boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(nonNegativeIntegerVisitor)));
    //   break;
    }
}

void
Interest::Deserialize (Ptr<ndn::Interest> interest, InputIterator &start)
{
  static InterestVisitor interestVisitor;

  Ptr<NdnbParser::Block> root = NdnbParser::Block::ParseBlock (start);
  root->accept (interestVisitor, GetPointer (interest));
}

} // ndnb
} // wire

NDN_NAMESPACE_END
