/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_REGEX_COMPONENT_H
#define NDN_REGEX_COMPONENT_H

#include <boost/regex.hpp>

#include "ndn.cxx/common.h"

#include "regex-matcher.h"
#include "regex-pseudo-matcher.h"


using namespace std;


namespace ndn
{

namespace regex
{
    
  class RegexComponent : public RegexMatcher
  {
  public:
    ///////////////////////////////////////////////////////////////////////////////
    //                              CONSTRUCTORS                                 //
    ///////////////////////////////////////////////////////////////////////////////

    /**
     * @brief Create a RegexComponent matcher from expr
     * @param expr The standard regular expression to match a component
     * @param backRefManager The back reference manager
     * @param exact The flag to provide exact match
     */
    RegexComponent(const string & expr, Ptr<RegexBRManager> backRefManager, bool exact = true);
    
    virtual ~RegexComponent() {};

    virtual bool 
    match(const Name & name, const int & offset, const int &len = 1);

  protected:
    /**
     * @brief Compile the regular expression to generate the more matchers when necessary
     * @returns true if compiling succeeds
     */
    virtual void 
    compile();
    
  private:
    bool m_exact;
    boost::regex m_componentRegex;
    vector<Ptr<RegexPseudoMatcher> > m_pseudoMatcher;
    
  };

}//regex
    
}//ndn

#endif
