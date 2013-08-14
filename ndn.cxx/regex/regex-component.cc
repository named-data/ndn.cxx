/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <boost/regex.hpp>

#include "regex-component.h"

#include "logging.h"

INIT_LOGGER ("RegexComponent");

using namespace std;

namespace ndn
{

namespace regex
{
  RegexComponent::RegexComponent (const string & expr, Ptr<RegexBRManager> backRefManager, bool exact)
    : RegexMatcher (expr, EXPR_COMPONENT, backRefManager),
      m_exact(exact)
  {
    // _LOG_TRACE ("Enter RegexComponent Constructor: ");
    compile();
    // _LOG_TRACE ("Exit RegexComponent Constructor: ");
  }

  void 
  RegexComponent::compile ()
  {
    // _LOG_TRACE ("Enter RegexComponent::compile");

    m_componentRegex = boost::regex (m_expr);

    m_pseudoMatcher.clear();
    m_pseudoMatcher.push_back(Ptr<RegexPseudoMatcher>());

    for (int i = 1; i < m_componentRegex.mark_count(); i++)
      {
        Ptr<RegexPseudoMatcher> pMatcher = Ptr<RegexPseudoMatcher>::Create();
        m_pseudoMatcher.push_back(pMatcher);
        m_backRefManager->pushRef(boost::static_pointer_cast<RegexMatcher>(pMatcher));
      }
    

    // _LOG_TRACE ("Exit RegexComponent::compile");
  }

  bool
  RegexComponent::match (const Name & name, const int & offset, const int & len)
  {
    // _LOG_TRACE ("Enter RegexComponent::match ");

    m_matchResult.clear();

    if("" == m_expr)
      {
        m_matchResult.push_back(name.get(offset));
        return true;
      }

    if(true == m_exact)
      {
        boost::smatch subResult;
        string targetStr = name.get(offset).toUri();
        if(boost::regex_match(targetStr, subResult, m_componentRegex))
          {
            for (int i = 1; i < m_componentRegex.mark_count(); i++)
              {
                m_pseudoMatcher[i]->resetMatchResult();
                m_pseudoMatcher[i]->setMatchResult(subResult[i]);
              }
            m_matchResult.push_back(name.get(offset));
            return true;
          }
      }
    else
      {
        throw RegexException("Non-exact component search is not supported yet!");
      }

    return false;
  }

  // bool 
  // RegexComponent::cMatch(Name name, const int & offset, const int & len)
  // {
  //   _LOG_DEBUG ("Enter RegexComponent::Match: ");
  //   _LOG_DEBUG ("name : "<< name << " offset : " << offset << " len: " << len);

  //   m_matchResult = Name();

  //   if(0 == len)
  //     return false;

  //   if(m_exact == true){
  //     if(boost::regex_match(name.get(offset).toUri(), boost::regex(m_expr))){
  //       m_matchResult.append(name.get(offset));
  //       return true;
  //     }
  //     else
  //       return false;
  //   }
  //   else{
  //     if(boost::regex_search(name.get(offset).toUri(), boost::regex(m_expr))){
  //       m_matchResult.append(name.get(offset));
  //       return true;
  //     }
  //     else
  //       return false;
  //   }
  // }


} //regex

} //ndn
