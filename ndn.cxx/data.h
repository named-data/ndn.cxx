/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the COPYING file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_DATA_H
#define NDN_DATA_H

#include "ndn.cxx/fields/name.h"

namespace ndn {

/**
 * @brief Class implementing abstractions to work with NDN Data packets
 */
class Data
{
public:
  /**
   * @brief Create an empty Data with empty payload
   **/
  Data ();

  /**
   * @brief Set data packet name
   * @param name name of the data packet
   * @return reference to self (to allow method chaining)
   *
   * In some cases, a direct access to and manipulation of name using getName is more efficient
   */
  inline Data &
  setName (const Name &name);

  /**
   * @brief Get data packet name (const reference)
   * @returns name of the data packet
   */
  inline const Name &
  getName () const;

  /**
   * @brief Get data packet name (reference)
   * @returns name of the data packet
   */
  inline Name &
  getName ();

  // /**
  //  * @brief Set content object timestamp
  //  * @param timestamp timestamp
  //  */
  // void
  // SetTimestamp (const Time &timestamp);

  // /**
  //  * @brief Get timestamp of the content object
  //  */
  // Time
  // GetTimestamp () const;

  // /**
  //  * @brief Set freshness of the content object
  //  * @param freshness Freshness, 0s means infinity
  //  */
  // void
  // SetFreshness (const Time &freshness);

  // /**
  //  * @brief Get freshness of the content object
  //  */
  // Time
  // GetFreshness () const;

  // /**
  //  * @brief Set "fake" signature on the content object
  //  * @param signature  uint32_t number, simulating content object signature
  //  *
  //  * Values for the signature totally depend on the application
  //  */
  // void
  // SetSignature (uint32_t signature);

  // /**
  //  * @brief Get "fake" signature of the content object
  //  *
  //  * Values for the signature totally depend on the application
  //  */
  // uint32_t
  // GetSignature () const;

private:
  Name m_name;
  // Time m_freshness;
  // Time m_timestamp;
  // uint32_t m_signature; // 0, means no signature, any other value application dependent (not a real signature)
};

inline Data &
Data::setName (const Name &name)
{
  m_name = name;
  return *this;
}

inline const Name &
Data::getName () const
{
  return m_name;
}

inline Name &
Data::getName ()
{
  return m_name;
}

} // namespace ndn

#endif // NDN_DATA_H
