/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2013 University of California, Los Angeles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *	   Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_INTEREST_H
#define NDN_INTEREST_H

#include <ndn.cxx/common.h>
#include <ndn.cxx/name.h>
#include <ndn.cxx/hash.h>

#include <boost/date_time/posix_time/posix_time_types.hpp>

namespace ndn {

/**
 * @brief Exception that is thrown in case of error during interest construction or parsing
 */
struct InterestException:
    virtual boost::exception, virtual std::exception {};

class Interest
{
public:
  /**
   * @brief Default constructor, creates an interest for / prefix without any selectors
   */
  Interest ();

  /**
   * @brief Create an interest for the name
   * @param name name of the data to request
   */
  Interest (const Name &name);

  /**
   * @brief Copy constructor
   * @param interest interest to copy
   */
  Interest (const Interest &interest);

  /**
   * @brief Create an interest based on ccn_parsed_interest data structure
   * @param interest pointer to ccn_parsed_interest data structure
   *
   * This method will create an interest with empty name, since ccn_parsed_interest structure
   * has limited amount of information
   */
  Interest (const ccn_parsed_interest *interest);

  /**
   * @brief Set interest name
   * @param name name of the interest
   * @return reference to self (to allow method chaining)
   */
  inline Interest &
  setName (const Name &name);

  /**
   * @brief Get interest name
   * @returns name of the interest
   */
  inline const Name &
  getName () const;
  
  /**
   * @brief Set interest lifetime (time_duration)
   * @param interestLifetime interest lifetime specified as a time_duration value.
   *        Negative value means that InterestLifetime is not set.
   * @return reference to self (to allow method chaining)
   */
  inline Interest &
  setInterstLifetime (const boost::posix_time::time_duration &interestLifetime);

  /**
   * @brief Set interest lifetime (double)
   * @param interestLifetime interest lifetime expressed in seconds, with possible fractional seconds (double).
   *        Negative value means that InterestLifetime is not set.
   * @return reference to self (to allow method chaining)
   */
  inline Interest &
  setInterestLifetime (double interestLifetimeSeconds);

  /**
   * @brief Get interest lifetime
   * @return boost::posix_time::time_duration representing lifetime of the interest.
   *         Use time_duration::total_seconds () or time_duration::total_microseconds (),
   *         if you need interest lifetime as a plain number.
   *         @see http://www.boost.org/doc/libs/1_53_0/doc/html/date_time/posix_time.html
   */
  inline const boost::posix_time::time_duration &
  getInterestLifetime () const;
  
  /**
   * @brief Set intended interest scope
   * @param scope requested scope of the interest @see Scope
   * @return reference to self (to allow method chaining)
   */
  inline Interest &
  setScope (uint8_t scope);

  /**
   * @brief Get intended interest scope
   * @return intended interest scope @see Scope
   */
  inline uint8_t
  getScope () const;

  ///////////////////////////////////////////////////////////////////////
  //                          SELECTORS                                //
  ///////////////////////////////////////////////////////////////////////
  
  /**
   * @brief Enum defining constants for AnswerOriginKind selector field
   */
  enum AnswerOriginKind
  {
    AOK_CS = 0x1,
    AOK_NEW = 0x2,
    AOK_DEFAULT = 0x3, // (AOK_CS | AOK_NEW)
    AOK_STALE = 0x4,
    AOK_EXPIRE = 0x10
  };

  /**
   * @brief Enum defining constants for ChildSelector field
   */
  enum ChildSelector
    {
      CHILD_LEFT = 0,
      CHILD_RIGHT = 1,
      CHILD_DEFAULT = 2
    };

  /**
   * @brief Enum defining constants for Scope field
   */
  enum Scope
    {
      NO_SCOPE = 255,
      SCOPE_LOCAL_CCND = 0,
      SCOPE_LOCAL_HOST = 1,
      SCOPE_NEXT_HOST = 2
    };

  /**
   * @brief Set interest selector for maximum suffix components
   * @param maxSuffixComponents maximum number of suffix components. If Interest::ncomps, then not restricted
   * @return reference to self (to allow method chaining)
   */
  inline Interest &
  setMaxSuffixComponents (uint32_t maxSuffixComponents);

  /**
   * \brief Get interest selector for maximum suffix components
   *
   * MaxSuffixComponents refer to the number of name components beyond those in the prefix, 
   * and counting the implicit digest, that may occur in the matching ContentObject.
   * For more information, see http://www.ccnx.org/releases/latest/doc/technical/InterestMessage.html
   **/
  inline uint32_t
  getMaxSuffixComponents () const;
  
  /**
   * @brief Set interest selector for minimum suffix components
   * @param minSuffixComponents minimum number of suffix components. If Interest::ncomps, then not restricted
   * @return reference to self (to allow method chaining)
   */
  inline Interest &
  setMinSuffixComponents (uint32_t minSuffixComponents);
  
  /**
   * \brief Get interest selector for minimum suffix components
   *
   * MinSuffixComponents refer to the number of name components beyond those in the prefix, 
   * and counting the implicit digest, that may occur in the matching ContentObject.
   * For more information, see http://www.ccnx.org/releases/latest/doc/technical/InterestMessage.html
   **/
  inline uint32_t
  getMinSuffixComponents () const;

  /**
   * @brief Set interest selector for answer origin kind
   * @param answerOriginKind type of answer @see AnswerOriginKind
   * @return reference to self (to allow method chaining)
   */
  inline Interest &
  setAnswerOriginKind (uint32_t answerOriginKind);
  
  inline uint32_t
  getAnswerOriginKind () const;

  /**
   * @brief Set interest selector for child selector
   * @param child child selector @see ChildSelector
   * @return reference to self (to allow method chaining)
   *
   * Often a given interest will match more than one ContentObject within a given content store. 
   * The ChildSelector provides a way of expressing a preference for which of these should be returned. 
   * If the value is false, the leftmost child is preferred. If true, the rightmost child is preferred.
   * \see http://www.ccnx.org/releases/latest/doc/technical/InterestMessage.html for more information. 
   */
  inline Interest &
  setChildSelector (uint8_t child);

  /**
   * @brief Get interest selector for child selector
   */
  inline uint8_t
  getChildSelector () const;

  /**
   * @brief Set interest selector for publisher public key digest
   * @param digest publisher public key digest
   * @return reference to self (to allow method chaining)
   *
   * Currently, this method has no effect
   * @todo Implement PublisherPublicKeyDigest
   */
  inline Interest &
  setPublisherPublicKeyDigest(const Hash &digest);

  /**
   * @brief Get interest selector for publisher public key digest
   *
   * @todo Implement
   */
  inline const Hash&
  getPublisherPublicKeyDigest () const;

  ///////////////////////////////////////////////////////////////////////
  //                           HELPERS                                 //
  ///////////////////////////////////////////////////////////////////////

  
  /**
   * @brief Convert to wire format and return it in form of ndn::CharbufPtr
   */
  CharbufPtr
  toCharbuf () const;

  /**
   * @brief Convert to wire format   
   */
  std::ostream &
  toWire (std::ostream &os);

  /**
   * @brief Compare equality of two interests
   */
  bool
  operator== (const Interest &interest);

public:
  // Data Members (public):
  ///  Value returned by various member functions when they fail.
  const static uint32_t ncomps = static_cast<uint32_t> (-1);

private:
  Name m_name;
  uint32_t m_maxSuffixComponents;
  uint32_t m_minSuffixComponents;
  uint32_t m_answerOriginKind;
  boost::posix_time::time_duration m_interestLifetime; // lifetime in seconds
  
  uint8_t m_scope;
  uint8_t m_childSelector;
  // not used now
  Hash m_publisherPublicKeyDigest;
};

typedef boost::shared_ptr<Interest> InterestPtr;

inline Interest &
Interest::setName (const Name &name)
{
  m_name = name;
  return *this;
}

inline const Name &
Interest::getName () const
{
  return m_name;
}
  
inline Interest &
Interest::setInterstLifetime (const boost::posix_time::time_duration &interestLifetime)
{
  m_interestLifetime = interestLifetime;
  return *this;
}

inline Interest &
Interest::setInterestLifetime (double interestLifetimeSeconds)
{
  double seconds, microseconds;
  seconds = std::modf (interestLifetimeSeconds, &microseconds);
  microseconds *= 1000000;
  
  m_interestLifetime = boost::posix_time::seconds (seconds) + boost::posix_time::microseconds (microseconds);
  return *this;
}

inline const boost::posix_time::time_duration &
Interest::getInterestLifetime () const
{
  return m_interestLifetime;
}
  
inline Interest &
Interest::setScope (uint8_t scope)
{
  m_scope = scope;
  return *this;
}

inline uint8_t
Interest::getScope () const
{
  return m_scope;
}

///////////////////////////////////////////////////////////////////////
//                          SELECTORS                                //
///////////////////////////////////////////////////////////////////////
  

inline Interest &
Interest::setMaxSuffixComponents (uint32_t maxSuffixComponents)
{
  m_maxSuffixComponents = maxSuffixComponents;
  return *this;
}

inline uint32_t
Interest::getMaxSuffixComponents () const
{
  return m_maxSuffixComponents;
}
  
inline Interest &
Interest::setMinSuffixComponents (uint32_t minSuffixComponents)
{
  m_minSuffixComponents = minSuffixComponents;
  return *this;
}
  
inline uint32_t
Interest::getMinSuffixComponents () const
{
  return m_minSuffixComponents;
}

inline Interest &
Interest::setAnswerOriginKind (uint32_t answerOriginKind)
{
  m_answerOriginKind = answerOriginKind;
  return *this;
}
  
inline uint32_t
Interest::getAnswerOriginKind () const
{
  return m_answerOriginKind;
}

inline Interest &
Interest::setChildSelector (uint8_t childSelector)
{
  m_childSelector = childSelector;
  return *this;
}

inline uint8_t
Interest::getChildSelector () const
{
  return m_childSelector;
}

inline Interest &
Interest::setPublisherPublicKeyDigest(const Hash &publisherPublicKeyDigest)
{
  m_publisherPublicKeyDigest = publisherPublicKeyDigest;
  return *this;
}

inline const Hash&
Interest::getPublisherPublicKeyDigest () const
{
  return m_publisherPublicKeyDigest;
}

} // ndn

#endif // NDN_INTEREST_H
