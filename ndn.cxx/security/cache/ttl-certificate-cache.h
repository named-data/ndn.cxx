/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_TTL_CERTIFICATE_CACHE_H
#define NDN_TTL_CERTIFICATE_CACHE_H

#include "certificate-cache.h"

#include <boost/thread/locks.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/thread.hpp>

#include <unistd.h>
#include <map>

namespace ndn
{

namespace security
{
  class TTLCertificateCache : public CertificateCache
  {
  protected:
    typedef std::list<Name> TrackerList;
    
    class TTLCacheEntry
    {
    public:
      TTLCacheEntry(const Time & timestamp, Ptr<Certificate> certificate, TrackerList::iterator it)
        : m_timestamp(timestamp)
        , m_certificate(certificate)
        , m_it(it)
      {}

      Time m_timestamp;
      Ptr<Certificate> m_certificate;
      TrackerList::iterator m_it;
    };
    
    typedef boost::recursive_mutex RecLock;
    typedef boost::unique_lock<RecLock> UniqueRecLock;
    typedef std::map<Name, TTLCacheEntry> Cache;

  public:
    TTLCertificateCache(int maxSize = 1000, int interval = 60);
    
    virtual
    ~TTLCertificateCache();

    void
    start();
    
    void
    shutdown();
    
    virtual void
    insertCertificate(Ptr<Certificate> certificate);

    virtual Ptr<Certificate> 
    getCertificate(const Name & certificateName);

    void
    printContent();
    
  private:
    void
    cleanLoop();
    
  protected:

    int m_maxSize;
    Cache m_cache;
    TrackerList m_lruList;
    RecLock m_mutex;
    boost::thread m_thread;
    bool m_running;
    int m_interval;
  };
}

}//ndn

#endif
