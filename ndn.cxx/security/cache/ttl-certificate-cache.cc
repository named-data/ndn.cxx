/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ttl-certificate-cache.h"

#include <boost/date_time/posix_time/posix_time.hpp>

#include "logging.h"

#include <iostream>

using namespace std;
using namespace boost;

INIT_LOGGER("ndn.security.TTLCertificateCache")

namespace ndn
{

namespace security
{

  // TTLCacheEntry::TTLCacheEntry (const Time & timestamp, const Certificate & certificate)
  //   : m_timestamp(timestamp)
  //   , m_certificate(certificate)
  // {}
    
  TTLCertificateCache::TTLCertificateCache(int maxSize, int interval)
    : m_maxSize(maxSize)
    , m_running(true)
    , m_interval(interval)
  {
    start();
  }

  TTLCertificateCache::~TTLCertificateCache()
  {
    shutdown();
  }

  void
  TTLCertificateCache::start()
  {
    m_thread = thread (&TTLCertificateCache::cleanLoop, this);
  }

  void
  TTLCertificateCache::shutdown()
  {

    {
      UniqueRecLock lock(m_mutex);
      m_running = false;
    }    
    m_thread.interrupt();
    m_thread.join ();

  }
  
  void
  TTLCertificateCache::insertCertificate(Ptr<Certificate> certificate)
  {
    Name name = certificate->getName().getPrefix(certificate->getName().size()-1);
    Time expire = time::Now() + certificate->getContent().getFreshness();
    
    {
      UniqueRecLock lock(m_mutex);
      Cache::iterator it = m_cache.find(name);
      if(it != m_cache.end())
        {
          m_lruList.splice(m_lruList.end(), m_lruList, it->second.m_it);
          it->second.m_timestamp = expire;
          it->second.m_certificate = certificate;
        }
      else
        {
          while(m_lruList.size() >= m_maxSize)
            {
              m_cache.erase(m_lruList.front());
              m_lruList.pop_front();
            }
          TrackerList::iterator it = m_lruList.insert(m_lruList.end(), name);
          TTLCacheEntry cacheEntry(expire, certificate, it);
          m_cache.insert(pair <Name, TTLCacheEntry> (name, cacheEntry));
        }
    }
  }

  Ptr<Certificate> 
  TTLCertificateCache::getCertificate(const Name & certName, bool hasVersion)
  {
    Name certificateName;
    if(hasVersion)
      certificateName = certName.getPrefix(certName.size()-1);
    else
      certificateName = certName;
    {
      UniqueRecLock lock(m_mutex);
      Cache::iterator it = m_cache.find(certificateName);
      if(it != m_cache.end())
        {
          m_lruList.splice(m_lruList.end(), m_lruList, it->second.m_it);
          return it->second.m_certificate;
        }
      else
        return NULL;
    }
  }
  
  void
  TTLCertificateCache::cleanLoop()
  {
    while(m_running)
      {
        Time now = time::Now();
        {
          UniqueRecLock lock(m_mutex);
          // _LOG_DEBUG("Round: " << boost::posix_time::to_iso_string(now));
          Cache::iterator it = m_cache.begin();
          while(it != m_cache.end())
            {
              // _LOG_DEBUG("size: " << m_cache.size() << " " << it->second.m_it->toUri() << " timestamp: " << boost::posix_time::to_iso_string(it->second.m_timestamp));
              if(now > it->second.m_timestamp)
                {
                  Cache::iterator tmp = it;
                  tmp++;
                  
                  // _LOG_DEBUG("ERASE");
                  m_lruList.erase(it->second.m_it);
                  m_cache.erase(it);

                  it = tmp;
                }
              else
                {
                  it ++;
                }
            }
        }        
        try{
#if BOOST_VERSION >= 1050000
          this_thread::sleep_for(chrono::seconds(m_interval));
#else
          this_thread::sleep(posix_time::seconds(m_interval));
#endif
        }catch(thread_interrupted& e){
          break;
        }
      }
  }

  void
  TTLCertificateCache::printContent()
  {
    TrackerList::iterator it = m_lruList.begin();
    for(; it != m_lruList.end(); it++)
        cout << it->toUri() << " ";
    cout << endl;
  }


}//security

}//ndn

