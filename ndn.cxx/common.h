/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *                     Zhenkai Zhu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_COMMON_H
#define NDN_COMMON_H

#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/function.hpp>

#define ndn ndn_client
extern "C" {
#include <ndn/ndn.h>
}
#undef ndn
#undef NDN_CLOSE
#undef NDN_TT_BITS
#undef NDN_TT_HBIT
#undef NDN_TT_MASK
#undef NDN_MAX_TINY

namespace ndn
{
template<class T>
struct Ptr : public boost::shared_ptr<T>
{
  Ptr () { }
  Ptr (boost::shared_ptr<T> ptr) : boost::shared_ptr<T>(ptr) { }
  Ptr (T *ptr) :  boost::shared_ptr<T>(ptr) { }
  Ptr (T *ptr,bool) :  boost::shared_ptr<T>(ptr) { }

  template<class Y>
  Ptr & operator = (boost::shared_ptr<Y> ptr)
  {
    boost::static_pointer_cast<T> (ptr).swap (*this);
    // *this = boost::static_pointer_cast<T> (ptr);
    return *this;
  }

  operator Ptr<const T> () const { return boost::shared_ptr<const T> (*this); }

  // template<class B>
  // operator Ptr<B> () { return *this; }

  static Ptr
  Create () { return boost::make_shared<T> (); }

  template<class U>
  operator Ptr<U> () { return boost::static_pointer_cast<U> (*this); }

  template<class U>
  operator Ptr<const U> () const { return boost::static_pointer_cast<const U> (*this); }
};

template<class T>
inline T*
GetPointer (Ptr<T> p)
{
  return p.get ();
}

template<class T>
Ptr<T> Create() { return Ptr<T> (new T()); }

template<class T, class P1>
Ptr<T> Create(P1 &p1) { return Ptr<T> (new T(p1)); }

template<class T, class P1, class P2>
Ptr<T> Create(P1 &p1, P2 p2) { return Ptr<T> (new T(p1, p2)); }

template<class T, class P1, class P2, class P3>
Ptr<T> Create(P1 &p1, P2 p2, P3 p3) { return Ptr<T> (new T(p1, p2, p3)); }

//template<class To, class From>
//boost::shared_ptr<T> StaticCast (From &
template<class T, class U>
Ptr<T> StaticCast(Ptr<U> const & r) { return boost::static_pointer_cast<T>(r); }

template<class T, class U>
Ptr<T> DynamicCast(Ptr<U> const & r) { return boost::dynamic_pointer_cast<T>(r); }

// typedef u_char uint8_t; // types.h defines  u_char

class InputIterator : public std::istream
{
public:
  uint8_t ReadU8 () { return static_cast<uint8_t> (get ()); }
  uint8_t PeekU8 () { return static_cast<uint8_t> (peek ()); }
  bool IsEnd () const { return eof(); }
  void Prev () { seekg(-1, std::ios_base::cur); }
};

class OutputIterator : public std::ostream
{
public:
  void Write (const uint8_t * s, uint32_t n) { write (reinterpret_cast<const char*> (s),n); }
  void WriteU8 (const uint8_t s) { put (s); }
  void WriteU8 (const uint8_t s, uint32_t n) { for (uint32_t i = 0; i < n; i++) { put (s); } }
};

typedef boost::posix_time::ptime Time;
typedef boost::posix_time::time_duration TimeInterval;

namespace time
{
inline TimeInterval Seconds (int secs) { return boost::posix_time::seconds (secs); }
inline TimeInterval Milliseconds (int msecs) { return boost::posix_time::milliseconds (msecs); }
inline TimeInterval Microseconds (int musecs) { return boost::posix_time::microseconds (musecs); }

inline TimeInterval Seconds (double fractionalSeconds)
{
  double seconds, microseconds;
  seconds = std::modf (fractionalSeconds, &microseconds);
  microseconds *= 1000000;

  return time::Seconds((int)seconds) + time::Microseconds((int)microseconds);
}

inline Time Now () { return boost::posix_time::microsec_clock::universal_time (); }

const Time UNIX_EPOCH_TIME = Time (boost::gregorian::date (1970, boost::gregorian::Jan, 1));
inline TimeInterval NowUnixTimestamp ()
{
  return TimeInterval (time::Now () - UNIX_EPOCH_TIME);
}
} // time
} // ndn

#define NDN_NAMESPACE_BEGIN namespace ndn {
#define NDN_NAMESPACE_END   }

template<class T>
struct SimpleRefCount
{
};

#endif // NDN_COMMON_H
