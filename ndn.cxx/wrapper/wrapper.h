/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *                     Zhenkai Zhu
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 *         Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_WRAPPER_H
#define NDN_WRAPPER_H

#include <boost/thread/locks.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/thread.hpp>

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/name.h"
#include "ndn.cxx/interest.h"
#include "ndn.cxx/security/keychain.h"

#include "closure.h"


class Executor;

namespace ndn {
  namespace security {
    class Keychain;
  }

  class Wrapper
  {
  public:
    const static int MAX_FRESHNESS = 2147; // max value for ndnx
    const static int DEFAULT_FRESHNESS = 60;
    typedef boost::function<void (Ptr<Interest>)> InterestCallback;

    Wrapper(Ptr<security::Keychain> keychain = Ptr<security::Keychain>::Create());
    ~Wrapper();
    
    void
    start (); // called automatically in constructor

    /**
     * @brief Because of uncertainty with executor, in some case it is necessary to call shutdown explicitly (see test-server-and-fetch.cc)
     */
    void
    shutdown (); // called in destructor, but can called manually

    int
    setInterestFilter (const Name &prefix, const InterestCallback &interestCallback, bool record = true);
    
    void
    clearInterestFilter (const Name &prefix, bool record = true);

    int
    sendInterest (Ptr<Interest> interest, Ptr<Closure> closurePtr);

    int
    publishDataByCert (const Name &name, 
                       const unsigned char *buf, 
                       size_t len, 
                       const Name & certificateName, 
                       int freshness = DEFAULT_FRESHNESS);

    inline int
    publishDataByCert (const Name &name, 
                       const Blob &content, 
                       const Name & certificateName, 
                       int freshness = DEFAULT_FRESHNESS);

    inline int
    publishDataByCert (const Name &name, 
                       const std::string &content, 
                       const Name & certificateName, 
                       int freshness = DEFAULT_FRESHNESS);

    int
    publishDataByIdentity (const Name &name, 
                           const unsigned char *buf, 
                           size_t len, 
                           const Name &identityName=Name(), 
                           int freshness = DEFAULT_FRESHNESS);

    inline int
    publishDataByIdentity (const Name &name, 
                           const Blob &content, 
                           const Name &identityName=Name(), 
                           int freshness = DEFAULT_FRESHNESS);

    inline int
    publishDataByIdentity (const Name &name, 
                           const std::string &content, 
                           const Name &identityName=Name(), 
                           int freshness = DEFAULT_FRESHNESS);

    // static Name
    // getLocalPrefix ();

    // Bytes
    // createContentObject(const Name &name, const void *buf, size_t len, int freshness = DEFAULT_FRESHNESS, const Name &keyNameParam=Name());

    int
    putToNdnd (const Blob &contentObject);

    // bool
    // verify(PcoPtr &pco, double maxWait = 1 /*seconds*/);

    // PcoPtr
    // get (const Interest &interest, double maxWait = 4.0/*seconds*/);

  private:
    Wrapper(const Wrapper &other) {}

    int
    publishDataByCert (Data &data, const Name & certificateName);

    int
    publishDataByIdentity (Data &data, const Name &identityName);

  protected:
    void
    connectNdnd();

    /// @cond include_hidden
    void
    ndnLoop ();
    
    /// @endcond

  protected:
    typedef boost::shared_mutex Lock;
    typedef boost::unique_lock<Lock> WriteLock;
    typedef boost::shared_lock<Lock> ReadLock;

    typedef boost::recursive_mutex RecLock;
    typedef boost::unique_lock<RecLock> UniqueRecLock;

    ndn_client* m_handle;
    RecLock m_mutex;
    boost::thread m_thread;
    bool m_running;
    bool m_connected;
    std::map<Name, InterestCallback> m_registeredInterests;
    Ptr<Executor> m_executor;
    Ptr<security::Keychain> m_keychain;
};

typedef boost::shared_ptr<Wrapper> WrapperPtr;

/**
 * @brief Namespace holding all exceptions that can be fired by the library
 */
namespace Error
{
struct ndnOperation : boost::exception, std::exception { };
}

inline int
Wrapper::publishDataByCert (const Name &name, const Blob &content, const Name & certificateName, int freshness)
{
  return publishDataByCert (name, reinterpret_cast<const unsigned char*>(content.buf()), content.size(), certificateName, freshness);
}

inline int
Wrapper::publishDataByIdentity (const Name &name, const Blob &content, const Name &identityName, int freshness)
{
  return publishDataByIdentity (name, reinterpret_cast<const unsigned char*>(content.buf()), content.size(), identityName, freshness);
}

inline int
Wrapper::publishDataByCert (const Name &name, const std::string &content, const Name & certificateName, int freshness)
{
  return publishDataByCert (name, reinterpret_cast<const unsigned char *> (content.c_str ()), content.size (), certificateName, freshness);
}

inline int
Wrapper::publishDataByIdentity (const Name &name, const std::string &content, const Name &identityName, int freshness)
{
  return publishDataByIdentity (name, reinterpret_cast<const unsigned char *> (content.c_str ()), content.size (), identityName, freshness);
}

} // ndn

#endif
