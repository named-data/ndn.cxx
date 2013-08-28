/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "wire-ccnb-interest.h"
#include "logging.h"

#include "wire-ccnb.h"


#include "ccnb-parser/visitors/name-visitor.h"
#include "ccnb-parser/visitors/non-negative-integer-visitor.h"
#include "ccnb-parser/visitors/timestamp-visitor.h"
#include "ccnb-parser/visitors/uint32t-blob-visitor.h"

#include "ccnb-parser/syntax-tree/block.h"
#include "ccnb-parser/syntax-tree/dtag.h"

#include <boost/foreach.hpp>
#include <boost/iostreams/stream.hpp>

INIT_LOGGER ("ndn.wire.Ccnb.Interest");

NDN_NAMESPACE_BEGIN

namespace wire {
namespace ccnb {

void
Interest::Serialize (const ndn::Interest &interest, OutputIterator &start)
{
  Ccnb::AppendBlockHeader (start, CcnbParser::NDN_DTAG_Interest, CcnbParser::NDN_DTAG); // <Interest>
  
  Ccnb::AppendBlockHeader (start, CcnbParser::NDN_DTAG_Name, CcnbParser::NDN_DTAG); // <Name>
  Ccnb::SerializeName (start, interest.getName());                // <Component>...</Component>...
  Ccnb::AppendCloser (start);                               // </Name>

  if (interest.getMinSuffixComponents () != ndn::Interest::ncomps)
    {
      Ccnb::AppendTaggedNumber (start, CcnbParser::NDN_DTAG_MinSuffixComponents, interest.getMinSuffixComponents ());
    }
  if (interest.getMaxSuffixComponents () != ndn::Interest::ncomps)
    {
      Ccnb::AppendTaggedNumber (start, CcnbParser::NDN_DTAG_MaxSuffixComponents, interest.getMaxSuffixComponents ());
    }
  // if (interest.getExclude ().size () > 0)
  //   {
  //     Ccnb::AppendExclude (start, interest.getExclude ());
  //   }
  if (interest.getChildSelector () != ndn::Interest::CHILD_DEFAULT)
    {
      Ccnb::AppendTaggedNumber (start, CcnbParser::NDN_DTAG_ChildSelector, interest.getChildSelector ());
    }
  if (interest.getAnswerOriginKind () != ndn::Interest::AOK_DEFAULT)
    {
      Ccnb::AppendTaggedNumber (start, CcnbParser::NDN_DTAG_AnswerOriginKind, interest.getAnswerOriginKind ());
    }
  if (interest.getScope () != ndn::Interest::NO_SCOPE)
    {
      Ccnb::AppendTaggedNumber (start, CcnbParser::NDN_DTAG_Scope, interest.getScope ());
    }
  if (!interest.getInterestLifetime ().is_negative ())
    {
      Ccnb::AppendBlockHeader (start, CcnbParser::NDN_DTAG_InterestLifetime, CcnbParser::NDN_DTAG);
      Ccnb::AppendTimestampBlob (start, interest.getInterestLifetime ());
      Ccnb::AppendCloser (start);
    }
  // if (interest.GetNonce()>0)
  //   {
  //     uint32_t nonce = interest.getNonce();
  //     Ccnb::AppendTaggedBlob (start, CcnbParser::NDN_DTAG_Nonce, nonce);
  //   }
    
  // if (interest.GetNack ()>0)
  //   {
  //     Ccnb::AppendBlockHeader (start, CcnbParser::NDN_DTAG_Nack, CcnbParser::NDN_DTAG);
  //     Ccnb::AppendNumber (start, interest.GetNack ());
  //     Ccnb::AppendCloser (start);
  //   }
  Ccnb::AppendCloser (start); // </Interest>
}

class InterestVisitor : public CcnbParser::VoidDepthFirstVisitor
{
public:
  virtual void visit (CcnbParser::Dtag &n, boost::any param/*should be CcnxInterest* */);
};

// We don't care about any other fields
void
InterestVisitor::visit (CcnbParser::Dtag &n, boost::any param/*should be Interest* */)
{
  // uint32_t n.m_dtag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;

  static CcnbParser::NonNegativeIntegerVisitor nonNegativeIntegerVisitor;
  static CcnbParser::NameVisitor               nameVisitor;
  static CcnbParser::TimestampVisitor          timestampVisitor;
  static CcnbParser::Uint32tBlobVisitor        nonceVisitor;
  
  ndn::Interest *m_interest = boost::any_cast<ndn::Interest*> (param);

  switch (n.m_dtag)
    {
    case CcnbParser::NDN_DTAG_Interest:
      _LOG_DEBUG ("Interest");
  
      // process nested blocks
      BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
        {
          block->accept (*this, param);
        }
      break;
    case CcnbParser::NDN_DTAG_Name:
      {
        _LOG_DEBUG ("Name");

        // process name components
        Name name;
        n.accept (nameVisitor, &name);
        m_interest->setName (name);
        break;
      }
    // case CcnbParser::NDN_DTAG_MinSuffixComponents:
    //   _LOG_DEBUG ("MinSuffixComponents");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw CcnbParser::CcnbDecodingException ();
    //   m_interest->SetMinSuffixComponents (
    //            boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonNegativeIntegerVisitor
    //                                                                        )));
    //   break;
    // case CcnbParser::NDN_DTAG_MaxSuffixComponents:
    //   _LOG_DEBUG ("MaxSuffixComponents");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw CcnbParser::CcnbDecodingException ();
    //   m_interest->SetMaxSuffixComponents (
    //            boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonNegativeIntegerVisitor
    //                                                                        )));
    //   break;
    // case CcnbParser::NDN_DTAG_Exclude:
    //   {
    //     _LOG_DEBUG ("Exclude");
    //     // process exclude components
    //     Ptr<Name> exclude = Create<Name> ();
        
    //     BOOST_FOREACH (Ptr<CcnbParser::Block> block, n.m_nestedTags)
    //       {
    //         block->accept (nameVisitor, &(*exclude));
    //       }
    //     m_interest->SetExclude (exclude);
    //     break;
    //   }
    // case CcnbParser::NDN_DTAG_ChildSelector:
    //   _LOG_DEBUG ("ChildSelector");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw CcnbParser::CcnbDecodingException ();

    //   m_interest->SetChildSelector (
    //            1 == boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonNegativeIntegerVisitor
    //                                                                        )));
    //   break;
    // case NDN_DTAG_AnswerOriginKind:
    //   _LOG_DEBUG ("AnswerOriginKind");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw CcnbParser::CcnbDecodingException ();
    //   m_interest->SetAnswerOriginKind (
    //            1 == boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonNegativeIntegerVisitor
    //                                                                        )));
    //   break;
    case CcnbParser::NDN_DTAG_Scope: 
      _LOG_DEBUG ("Scope");
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbParser::CcnbDecodingException ();
      m_interest->setScope (
               boost::any_cast<uint32_t> (
                                          (*n.m_nestedTags.begin())->accept(
                                                                           nonNegativeIntegerVisitor
                                                                           )));
      break;
    case CcnbParser::NDN_DTAG_InterestLifetime:
      _LOG_DEBUG ("InterestLifetime");
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbParser::CcnbDecodingException ();

      m_interest->setInterestLifetime (
               boost::any_cast<TimeInterval> (
                                      (*n.m_nestedTags.begin())->accept(
                                                                        timestampVisitor
                                                                        )));
      break;
    // case CcnbParser::NDN_DTAG_Nonce:
    //   _LOG_DEBUG ("Nonce");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw CcnbParser::CcnbDecodingException ();

    //   m_interest->SetNonce (
    //            boost::any_cast<uint32_t> (
    //                                       (*n.m_nestedTags.begin())->accept(
    //                                                                        nonceVisitor
    //                                                                        )));
    //   break;
    
            
    // case CcnbParser::NDN_DTAG_Nack:
    //   _LOG_DEBUG ("Nack");
    //   if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
    //     throw CcnbParser::CcnbDecodingException ();
            
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

  Ptr<CcnbParser::Block> root = CcnbParser::Block::ParseBlock (start);
  root->accept (interestVisitor, GetPointer (interest));
}

} // ccnb
} // wire

NDN_NAMESPACE_END
