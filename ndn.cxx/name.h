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

#ifndef NDN_NAME_H
#define NDN_NAME_H

#include <boost/shared_ptr.hpp>
#include "ndn.cxx/common.h"
#include "ndn.cxx/charbuf.h"

namespace ndn {

/**
 * @brief Class for NDN Name
 */
class Name
{
public:
  typedef std::vector<Bytes>::iterator iterator;
  typedef std::vector<Bytes>::const_iterator const_iterator;
  typedef std::vector<Bytes>::reverse_iterator reverse_iterator;
  typedef std::vector<Bytes>::const_reverse_iterator const_reverse_iterator;
  typedef std::vector<Bytes>::reference reference;
  typedef std::vector<Bytes>::const_reference const_reference;
  
  ///////////////////////////////////////////////////////////////////////////////
  //                              CONSTRUCTORS                                 //
  ///////////////////////////////////////////////////////////////////////////////

  /**
   * @brief Default constructor to create an empty name (zero components, or "/")
   */
  Name ();

  /**
   * @brief Copy constructor
   *
   * @param other reference to a NDN name object
   */
  Name (const Name &other);

  /**
   * @brief Create a name from URL string
   *
   * @param url URI-represented name
   */
  Name (const std::string &url);

  /**
   * @brief Create a name from a vector of binary blobs, representing name components
   *
   * @param comps vector of binary blobs
   */
  Name (const std::vector<Bytes> &comps);

  /**
   * @brief Create a name from CCNB-formatted binary blob
   *
   * @param data pointer to the first byte of name in CCNB-formatted binary blob format
   * @param comps array of indices of name components inside the binary blob (@see ccn_indexbuf)
   */
  Name (const unsigned char *data, const ccn_indexbuf *comps);

  /**
   * @brief Create a name from CCNB-formatted binary blob
   *
   * @param data pointer to the first byte of name in CCNB-formatted binary blob format
   * @param length length of CCNB-formatted binary blob
   *
   * This version of the constructor first parses CCNB-formatted binary blob, discovers
   * the number of name components and their offsets, and then creates a new name object
   * based on the discovered information
   */
  Name (const void *data, const size_t length);

  /**
   * @brief Create a name from CCNB-formatted binary blob, represented by ndn::Charbuf object
   *
   * @param buf reference to ndn::Charbuf object, pointing to a buffer with CCNB-formatted binary blob
   */
  Name (const Charbuf &buf);

  /**
   * @brief Create a name from CCNB-formatted binary blob, represented by ccn_charbuf structure
   *
   * @param buf pointer to ccn_charbuf structure, pointing to a buffer with CCNB-formatted binary blob
   */
  Name (const ccn_charbuf *buf);

  /**
   * @brief Assignment operator
   */
  Name &
  operator= (const Name &other);

  
  ///////////////////////////////////////////////////////////////////////////////
  //                                SETTERS                                    //
  ///////////////////////////////////////////////////////////////////////////////

  /**
   * @brief Append components from another ndn::Name object
   *
   * @param comp reference to Name object
   * @returns reference to self (to allow chaining of append methods)
   */
  Name &
  append (const Name &comp);

  /**
   * @brief Append a binary blob as a name component
   *
   * @param comp a binary blob
   * @returns reference to self (to allow chaining of append methods)
   */
  Name &
  append (const Bytes &comp);

  /**
   * @brief Append a string as a name component
   *
   * @param compStr a string
   * @returns reference to self (to allow chaining of append methods)
   *
   * No conversions will be done to the string.  The string is included in raw form,
   * without any leading '\0' symbols.
   */
  Name &
  append (const std::string &compStr);

  /**
   * @brief Append a binary blob as a name component
   *
   * @param buf pointer to the first byte of the binary blob
   * @param size length of the binary blob
   * @returns reference to self (to allow chaining of append methods)
   */
  Name &
  append (const void *buf, size_t size);

  /**
   * @brief Append network-ordered numeric component to the name
   *
   * @param number number to be encoded and added as a component
   *
   * Number is encoded and added in network order. Tail zero-bytes are not included.
   * For example, if the number is 1, then 1-byte binary blob will be added  0x01.
   * If the number is 256, then 2 binary blob will be added: 0x01 0x01
   *
   * If the number is zero, an empty component will be added
   */
  Name &
  appendNumber (uint64_t number);

  /**
   * @brief Append network-ordered numeric component to the name with marker
   *
   * @param number number to be encoded and added as a component
   * @param marker byte marker, specified by the desired naming convention
   *
   * Currently defined naming conventions of the marker:
   * - 0x00  sequence number
   * - 0xC1  control number
   * - 0xFB  block id
   * - 0xFD  version number
   *
   * This version is almost exactly as appendNumber, with exception that it adds initial marker.
   * The number is formatted in the exactly the same way.
   *
   * @see appendNumber
   */
  Name &
  appendNumberWithMarker (uint64_t number, unsigned char marker);

  /**
   * @brief Helper method to add sequence number to the name (marker = 0x00)
   * @param seqno sequence number
   * @see appendNumberWithMarker
   */
  inline Name &
  appendSeqNum (uint64_t seqno);

  /**
   * @brief Helper method to add control number to the name (marker = 0xC1)
   * @param control control number
   * @see appendNumberWithMarker
   */
  inline Name &
  appendControlNum (uint64_t control);

  /**
   * @brief Helper method to add block ID to the name (marker = 0xFB)
   * @param blkid block ID
   * @see appendNumberWithMarker
   */
  inline Name &
  appendBlkId (uint64_t blkid);

  /**
   * @brief Helper method to add version to the name (marker = 0xFD)
   * @param version fully formatted version in a desired format (e.g., timestamp).
   *                If version is Name::nversion, then the version number is automatically
   *                assigned based on UTC timestamp
   * @see appendNumberWithMarker
   */
  Name &
  appendVersion (uint64_t version = Name::nversion);

  ///////////////////////////////////////////////////////////////////////////////
  //                                GETTERS                                    //
  ///////////////////////////////////////////////////////////////////////////////

  /**
   * @brief Get number of the name components
   * @return number of name components
   */
  inline size_t
  size () const;

  /**
   * @brief Get binary blob of name component
   * @param index index of the name component.  If less than 0, then getting component from the back:
   *              get(-1) getting the last component, get(-2) is getting second component from back, etc.
   * @returns const reference to binary blob of the requested name component
   *
   * If index is out of range, an exception will be thrown
   */
  const Bytes &
  get (int index) const;

  /**
   * @brief Get binary blob of name component
   * @param index index of the name component.  If less than 0, then getting component from the back
   * @returns reference to binary blob of the requested name component
   *
   * If index is out of range, an exception will be thrown
   */
  Bytes &
  get (int index);

  /////
  ///// Iterator interface to name components
  /////
  inline Name::const_iterator
  begin () const;           ///< @brief Begin iterator (const)

  inline Name::iterator
  begin ();                 ///< @brief Begin iterator

  inline Name::const_iterator
  end () const;             ///< @brief End iterator (const)

  inline Name::iterator
  end ();                   ///< @brief End iterator

  inline Name::const_reverse_iterator
  rbegin () const;          ///< @brief Reverse begin iterator (const)

  inline Name::reverse_iterator
  rbegin ();                ///< @brief Reverse begin iterator

  inline Name::const_reverse_iterator
  rend () const;            ///< @brief Reverse end iterator (const)

  inline Name::reverse_iterator
  rend ();                  ///< @brief Reverse end iterator
  

  /////
  ///// Static helpers to convert name component to appropriate value
  /////

  /**
   * @brief Convert binary blob name component to std::string (no conversion is made)
   * @param comp name component to be converted
   * @see asUriString
   */  
  static std::string
  asString (const Bytes &comp);

  /**
   * @brief Convert binary blob name component to std::string, escaping all non-printable characters in URI format
   * @param comp name component to be converted
   * @see asString
   */
  static std::string
  asUriString (const Bytes &comp);
  
  /**
   * @brief Convert binary blob name component (network-ordered number) to number
   * @param comp name component to be converted
   */  
  static uint64_t
  asNumber (const Bytes &comp);

  /**
   * @brief Convert binary blob name component (network-ordered number) to number, using appropriate marker from the naming convention
   * @param comp name component to be converted
   * @param marker required marker from the naming convention
   *
   * If the required marker does not exist, an exception will be thrown
   */  
  static uint64_t
  asNumberWithMarker (const Bytes &comp, unsigned char marker);

  /**
   * @brief Convert binary blob name component, assuming sequence number naming convention (marker = 0x00)
   * @param comp name component to be converted
   * @see asNumberWithMarker
   */
  inline static uint64_t
  asSeqNum (const Bytes &);
  
  /**
   * @brief Convert binary blob name component, assuming control number naming convention (marker = 0xC1)
   * @param comp name component to be converted
   * @see asNumberWithMarker
   */
  inline static uint64_t
  asControlNum (const Bytes &);

  /**
   * @brief Convert binary blob name component, assuming block ID naming convention (marker = 0xFB)
   * @param comp name component to be converted
   * @see asNumberWithMarker
   */
  inline static uint64_t
  asBlkId (const Bytes &);

  /**
   * @brief Convert binary blob name component, assuming time-stamping version naming convention (marker = 0xFD)
   * @param comp name component to be converted
   * @see asNumberWithMarker
   */
  inline static uint64_t
  asVersion (const Bytes &);

  /**
   * @brief Get a new name, constructed as a subset of components
   * @param pos Position of the first component to be copied to the subname
   * @param len Number of components to be copied. Value Name::npos indicates that all components till the end of the name.
   */
  Name
  getSubName (size_t pos = 0, size_t len = npos) const;

  /**
   * @brief Get prefix of the name
   * @param len length of the prefix
   * @param skip number of components to skip from beginning of the name
   */
  inline Name
  getPrefix (size_t len, size_t skip = 0) const;

  /**
   * @brief Get postfix of the name
   * @param len length of the postfix
   * @param skip number of components to skip from end of the name
   */
  inline Name
  getPostfix (size_t len, size_t skip = 0) const;

  
  /**
   * @brief Get text representation of the name (URI)
   */
  std::string
  toUri () const;

  /////////////////////////////////////////////////
  // Helpers and compatibility wrappers
  
  /**
   * @brief Canonical comparison of two sequences
   *
   * Similar to <= comparison, but using CCNx canonical ordering
   * @see http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
   */
  static bool
  canonical_compare (const Bytes &comp1, const Bytes &comp2);
  
  /**
   * @brief Check if to Name objects are equal (have the same number of components with the same binary data)
   */
  bool
  operator == (const Name &name) const;

  /**
   * @brief Check if two Name objects are not equal
   */
  inline bool
  operator != (const Name &name) const;
  
  /**
   * @brief Less or equal comparison of two name objects
   */
  bool
  operator <= (const Name &name) const;

  /**
   * @brief Less comparison of two name objects
   */
  bool
  operator < (const Name &name) const;

  /**
   * @brief Great or equal comparison of two name objects
   */
  inline bool
  operator >= (const Name &name) const;

  /**
   * @brief Great comparison of two name objects
   */
  inline bool
  operator > (const Name &name) const;
  
  /**
   * @brief Operator [] to simplify access to name components
   * @see get
   */
  inline Bytes &
  operator [] (int index);
  
  /**
   * @brief Operator [] to simplify access to name components
   * @see get
   */
  inline const Bytes &
  operator [] (int index) const;

  /**
   * @brief Create a new Name object, by copying components from first and second name
   */
  Name
  operator + (const Name &name) const;

  /**
   * @brief A wrapper for append method
   */
  template<class T>
  inline void
  push_back (const T &comp);

public:
  // Data Members (public):
  ///  Value returned by various member functions when they fail.
  const static size_t npos = static_cast<size_t> (-1);
  const static uint64_t nversion = static_cast<uint64_t> (-1);

private:
  std::vector<Bytes> m_comps;
};

typedef boost::shared_ptr<Name> NamePtr;

namespace Error
{
/**
 * @brief An exception indicating an unrecoverable error with Name
 *
 * Example how to print out diagnostic information when the exception is thrown
 * @code
 *     try
 *       {
 *         ... operations with ndn::Name
 *       }
 *     catch (boost::exception &e)
 *       {
 *         std::cerr << boost::diagnostic_information (e) << std::endl;
 *       }
 * @endcode
 */
struct Name : public virtual boost::exception, public virtual std::exception {};

}

std::ostream&
operator <<(std::ostream &os, const Name &name);


inline Name &
Name::appendSeqNum (uint64_t seqno)
{
  return appendNumberWithMarker (seqno, 0x00);
}

inline Name &
Name::appendControlNum (uint64_t control)
{
  return appendNumberWithMarker (control, 0xC1);
}

inline Name &
Name::appendBlkId (uint64_t blkid)
{
  return appendNumberWithMarker (blkid, 0xFB);
}

inline size_t
Name::size () const
{
  return m_comps.size ();
}

/////
///// Iterator interface to name components
/////
inline Name::const_iterator
Name::begin () const
{
  return m_comps.begin ();
}

inline Name::iterator
Name::begin ()
{
  return m_comps.begin ();
}

inline Name::const_iterator
Name::end () const
{
  return m_comps.end ();
}

inline Name::iterator
Name::end ()
{
  return m_comps.end ();
}

inline Name::const_reverse_iterator
Name::rbegin () const
{
  return m_comps.rbegin ();
}

inline Name::reverse_iterator
Name::rbegin ()
{
  return m_comps.rbegin ();
}

inline Name::const_reverse_iterator
Name::rend () const
{
  return m_comps.rend ();
}


inline Name::reverse_iterator
Name::rend ()
{
  return m_comps.rend ();
}


//// helpers

inline uint64_t
Name::asSeqNum (const Bytes &bytes)
{
  return Name::asNumberWithMarker (bytes, 0x00);
}
  
inline uint64_t
Name::asControlNum (const Bytes &bytes)
{
  return Name::asNumberWithMarker (bytes, 0xC1);
}

inline uint64_t
Name::asBlkId (const Bytes &bytes)
{
  return Name::asNumberWithMarker (bytes, 0xFB);
}

inline uint64_t
Name::asVersion (const Bytes &bytes)
{
  return Name::asNumberWithMarker (bytes, 0xFD);
}


inline Name
Name::getPrefix (size_t len, size_t skip/* = 0*/) const
{
  return getSubName (skip, len);
}

inline Name
Name::getPostfix (size_t len, size_t skip/* = 0*/) const
{
  return getSubName (size () - len - skip, len);
}


template<class T>
inline void
Name::push_back (const T &comp)
{
  append (comp);
}

inline bool
Name::operator !=(const Name &name) const
{
  return ! (*this == name);
}

inline bool
Name::operator >= (const Name &name) const
{
  return ! (*this < name);
}

inline bool
Name::operator > (const Name &name) const
{
  return ! (*this <= name);
}

inline Bytes &
Name::operator [] (int index)
{
  return get (index);
}
  
inline const Bytes &
Name::operator [] (int index) const
{
  return get (index);
}

} // ndn

#endif
