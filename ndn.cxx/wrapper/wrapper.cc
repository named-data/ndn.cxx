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

#include "wrapper.h"


extern "C" {
#include <ccn/fetch.h>
}
#include <poll.h>
#include <boost/throw_exception.hpp>
#include <boost/random.hpp>
#include <boost/make_shared.hpp>
#include <boost/algorithm/string.hpp>

#include "charbuf.h"

#include <sstream>

#include "executor/executor.h"

#include "logging.h"
#include "ndn.cxx/wire/ccnb.h"

INIT_LOGGER ("ndn.Wrapper");

typedef boost::error_info<struct tag_errmsg, std::string> errmsg_info_str;
typedef boost::error_info<struct tag_errmsg, int> errmsg_info_int;

using namespace std;
using namespace boost;

namespace ndn {

  Wrapper::Wrapper(Ptr<security::Keychain> keychain)
    : m_handle (0)
    , m_running (true)
    , m_connected (false)
    , m_executor (new Executor(1))
    , m_keychain (keychain)
  {
    m_keychain->setWrapper(this);
    start ();
  }

  void
  Wrapper::connectCcnd()
  {
    if (m_handle != 0) {
      ccn_disconnect (m_handle);
      //ccn_destroy (&m_handle);
    }
    else
      {
        m_handle = ccn_create ();
      }

    UniqueRecLock lock(m_mutex);
    if (ccn_connect(m_handle, NULL) < 0)
      {
        BOOST_THROW_EXCEPTION (Error::ndnOperation() << errmsg_info_str("connection to ccnd failed"));
      }
    m_connected = true;
    
    if (!m_registeredInterests.empty())
      {
        for (map<Name, InterestCallback>::const_iterator it = m_registeredInterests.begin(); it != m_registeredInterests.end(); ++it)
          {
            clearInterestFilter(it->first, false);
            setInterestFilter(it->first, it->second, false);
          }
      }
  }
  
  Wrapper::~Wrapper()
  {
    shutdown ();
    // if (m_verifier != 0)
    // {
    //   delete m_verifier;
    //   m_verifier = 0;
    // }
  }

  void
  Wrapper::start () // called automatically in constructor
  {
    connectCcnd();
    m_thread = thread (&Wrapper::ccnLoop, this);
    m_executor->start();
  }

  void
  Wrapper::shutdown () // called in destructor, but can called manually
  {
    m_executor->shutdown();

    {
      UniqueRecLock lock(m_mutex);
      m_running = false;
    }

    _LOG_DEBUG ("+++++++++SHUTDOWN+++++++");
    if (m_connected)
      {
        m_thread.join ();

        ccn_disconnect (m_handle);
      //ccn_destroy (&m_handle);
        m_connected = false;
      }
  }

  void
  Wrapper::ccnLoop ()
  {
    static boost::mt19937 randomGenerator (static_cast<unsigned int> (std::time (0)));
    static boost::variate_generator<boost::mt19937&, boost::uniform_int<> > rangeUniformRandom (randomGenerator, uniform_int<> (0,1000));

    while (m_running)
      {
        try
          {
            int res = 0;
            {
              UniqueRecLock lock(m_mutex);
              res = ccn_run (m_handle, 0);
            }

            if (!m_running) break;
            
            if (res < 0) {
              _LOG_ERROR ("ccn_run returned negative status: " << res);
              
              BOOST_THROW_EXCEPTION (Error::ndnOperation()
                                     << errmsg_info_str("ccn_run returned error"));
            }


            pollfd pfds[1];
            {
              UniqueRecLock lock(m_mutex);

              pfds[0].fd = ccn_get_connection_fd (m_handle);
              pfds[0].events = POLLIN;
              if (ccn_output_is_pending (m_handle))
                pfds[0].events |= POLLOUT;
            }

            int ret = poll (pfds, 1, 1);
            if (ret < 0)
              {
                BOOST_THROW_EXCEPTION (Error::ndnOperation() << errmsg_info_str("ccnd socket failed (probably ccnd got stopped)"));
              }
          }
        catch (Error::ndnOperation &e)
          {
            m_connected = false;
            // probably ccnd has been stopped
            // try reconnect with sleep
            int interval = 1;
            int maxInterval = 32;
            while (m_running)
              {
                try
                  {
                    this_thread::sleep (boost::get_system_time () +  time::Seconds (interval) + time::Milliseconds (rangeUniformRandom ()));

                    connectCcnd ();
                    _LOG_DEBUG("reconnect to ccnd succeeded");
                    break;
                  }
                catch (Error::ndnOperation &e)
                  {
                    this_thread::sleep (boost::get_system_time () +  time::Seconds (interval) + time::Milliseconds (rangeUniformRandom ()));

                    // do exponential backup for reconnect interval
                    if (interval < maxInterval)
                      {
                        interval *= 2;
                      }
                  }
              }
          }
        catch (const std::exception &exc)
          {
            // catch anything thrown within try block that derives from std::exception
            std::cerr << exc.what();
          }
        catch (...)
          {
            cout << "UNKNOWN EXCEPTION !!!" << endl;
          }
      }
  }

  int
  Wrapper::putToCcnd (const Blob & dataBlob)
  {
    _LOG_TRACE (">> putToCcnd");
    UniqueRecLock lock(m_mutex);
    if (!m_running || !m_connected)
      {
        _LOG_TRACE ("<< not running or connected");
        return -1;
      }


    if (ccn_put(m_handle, dataBlob.buf(), dataBlob.size()) < 0)
      {
        _LOG_ERROR ("ccn_put failed");
        // BOOST_THROW_EXCEPTION(Error::ndnOperation() << errmsg_info_str("ccnput failed"));
      }
    else
      {
        _LOG_DEBUG ("<< putToCcnd");
      }

    return 0;
  }

  int 
  Wrapper::publishDataByCert (Data &data, const Name & certificateName)
  {
    _LOG_TRACE("publishDataByCert: " << data.getName ());
    m_keychain->sign(data, certificateName);
    return putToCcnd(*data.encodeToWire());
  }

  int 
  Wrapper::publishDataByIdentity (Data &data, const Name &identityName)
  {
    _LOG_TRACE("publishDataByCert: " << data.getName ());
    m_keychain->signByIdentity(data, identityName);
    return putToCcnd(*data.encodeToWire());
  }

  int
  Wrapper::publishDataByCert (const Name &name, const unsigned char *buf, size_t len, const Name & certificateName, int freshness)
  {
    _LOG_TRACE ("publishData: " << name);

    Data data;
    data.setName(name);
    //TODO: Freshness processing
    Content content(buf, len, Content::DATA);
    data.setContent(content);

    return publishDataByCert(data, certificateName);
  }

  int
  Wrapper::publishDataByIdentity (const Name &name, const unsigned char *buf, size_t len, const Name &identityName, int freshness)
  {
    _LOG_TRACE ("publishData: " << name);

    Data data;
    data.setName(name);
    //TODO: Freshness processing
    Content content(buf, len, Content::DATA);
    data.setContent(content);

    return publishDataByIdentity(data, identityName);
  }

  static void
  deleteInInterestTuple (tuple<Wrapper::InterestCallback *, Ptr<Executor> > * tuple)
  {
    delete tuple->get<0> ();
    delete tuple;
  }

  static ccn_upcall_res
  incomingInterest(ccn_closure *selfp,
                   ccn_upcall_kind kind,
                   ccn_upcall_info *info)
  {
    Wrapper::InterestCallback *f;
    Ptr<Executor> executor;
    tuple<Wrapper::InterestCallback *, Ptr<Executor> > *realData = reinterpret_cast< tuple<Wrapper::InterestCallback *, Ptr<Executor> > * > (selfp->data);
    tie (f, executor) = *realData;

    switch (kind)
      {
      case CCN_UPCALL_FINAL: // effective in unit tests
        // delete closure;
        executor->execute (bind (deleteInInterestTuple, realData));

        delete selfp;
        _LOG_TRACE ("<< incomingInterest with CCN_UPCALL_FINAL");
        return CCN_UPCALL_RESULT_OK;

      case CCN_UPCALL_INTEREST:
        _LOG_TRACE (">> incomingInterest upcall: " << Name(info->interest_ccnb, info->interest_comps));
        break;

      default:
        _LOG_TRACE ("<< incomingInterest with CCN_UPCALL_RESULT_OK: " << Name(info->interest_ccnb, info->interest_comps));
        return CCN_UPCALL_RESULT_OK;
      }

    Ptr<Interest> interest = Ptr<Interest>( new Interest(info->pi));
    interest->setName (Name (info->interest_ccnb, info->interest_comps));

    executor->execute (bind (*f, interest));
    // this will be run in executor
    // (*f) (interest);
    // closure->runInterestCallback(interest);

    return CCN_UPCALL_RESULT_OK;
  }

  static void
  deleteInDataTuple (tuple<Ptr<Closure>, Ptr<Executor>, Ptr<Interest>, Ptr<security::Keychain> > *tuple)
  {
    // delete tuple->get<0> ();
    delete tuple;
  }

  static void
  onVerify(const Closure::DataCallback & dataCallback, Ptr<Data> data, Ptr<Executor> executor)
  {
    executor->execute (bind (dataCallback, data));
  }

  static void
  onVerifyError(const Closure::VerifyFailCallback & failCallback, Ptr<Interest> interest, Ptr<Executor> executor)
  {
    executor->execute (bind (failCallback, interest));
  }

  static ccn_upcall_res
  incomingData(ccn_closure *selfp,
               ccn_upcall_kind kind,
               ccn_upcall_info *info)
  {
    // Closure *cp = static_cast<Closure *> (selfp->data);
    Ptr<Closure> cp;
    Ptr<Executor> executor;
    Ptr<Interest> interest;
    Ptr<security::Keychain> keychain;
    tuple<Ptr<Closure>, Ptr<Executor>, Ptr<Interest>, Ptr<security::Keychain> > *realData = reinterpret_cast< tuple<Ptr<Closure>, Ptr<Executor>, Ptr<Interest>, Ptr<security::Keychain> > * > (selfp->data);
  tie (cp, executor, interest, keychain) = *realData;

    switch (kind)
      {
      case CCN_UPCALL_FINAL:  // effecitve in unit tests
        executor->execute (bind (deleteInDataTuple, realData));

        cp = NULL;
        delete selfp;
        _LOG_TRACE ("<< incomingData with CCN_UPCALL_FINAL");
        return CCN_UPCALL_RESULT_OK;

      case CCN_UPCALL_CONTENT:
        _LOG_TRACE (">> incomingData content upcall: " << Name (info->content_ccnb, info->content_comps));
        break;

        // this is the case where the intentionally unsigned packets coming (in Encapsulation case)
      case CCN_UPCALL_CONTENT_BAD:
        _LOG_TRACE (">> incomingData content bad upcall: " << Name (info->content_ccnb, info->content_comps));
        break;

        // always ask ccnd to try to fetch the key
      case CCN_UPCALL_CONTENT_UNVERIFIED:
        _LOG_TRACE (">> incomingData content unverified upcall: " << Name (info->content_ccnb, info->content_comps));
        break;

      case CCN_UPCALL_INTEREST_TIMED_OUT: {
        if (cp != NULL)
          {
            Name interestName (info->interest_ccnb, info->interest_comps);
            _LOG_TRACE ("<< incomingData timeout: " << Name (info->interest_ccnb, info->interest_comps));
            executor->execute (bind (cp->m_timeoutCallback, cp, interest));
          }
        else
          {
            _LOG_TRACE ("<< incomingData timeout, but callback is not set...: " << Name (info->interest_ccnb, info->interest_comps));
          }
        return CCN_UPCALL_RESULT_OK;
      }
      default:
        _LOG_TRACE(">> unknown upcall type");
        return CCN_UPCALL_RESULT_OK;
      }

    Ptr<Blob> blob = Ptr<Blob> (new Blob(info->content_ccnb, info->pco->offset[CCN_PCO_E]));
    Ptr<Data> data = Data::decodeFromWire(blob);

    if(cp->m_unverifiedDataCallback.empty())
      keychain->verifyData(data, boost::bind(onVerify, cp->m_dataCallback, _1, executor), bind(onVerifyError, cp->m_verifyFailCallback, interest, executor));
    else
      executor->execute (bind(cp->m_unverifiedDataCallback, data));
 
   _LOG_TRACE (">> incomingData");
    
    return CCN_UPCALL_RESULT_OK;
  }

  int Wrapper::sendInterest (Ptr<Interest> interestPtr, Ptr<Closure> closurePtr)
  {
    _LOG_TRACE (">> sendInterest: " << interestPtr->getName ());
    {
      UniqueRecLock lock(m_mutex);
      if (!m_running || !m_connected)
        {
          _LOG_ERROR ("<< sendInterest: not running or connected");
          return -1;
        }
    }
    
    ccn_closure *dataClosure = new ccn_closure;
    
    // Closure *myClosure = new ExecutorClosure(closure, m_executor);
    Ptr<Closure> myClosure = Ptr<Closure>(new Closure(*closurePtr));
    dataClosure->data = new tuple<Ptr<Closure>, Ptr<Executor>, Ptr<Interest>, Ptr<security::Keychain> > (myClosure, m_executor, interestPtr, m_keychain);
    
    dataClosure->p = &incomingData;
    
    UniqueRecLock lock(m_mutex);

    charbuf_stream nameStream;
    wire::Ccnb::appendName (nameStream, interestPtr->getName ());
  
    charbuf_stream interestStream;
    wire::Ccnb::appendInterest (interestStream, *interestPtr);

    if (ccn_express_interest (m_handle, nameStream.buf ().getBuf (),
                              dataClosure,
                              interestStream.buf ().getBuf ()
                              ) < 0)
      {
        _LOG_ERROR ("<< sendInterest: ccn_express_interest FAILED!!!");
      }

    return 0;
  }

  int Wrapper::setInterestFilter (const Name &prefix, const InterestCallback &interestCallback, bool record/* = true*/)
  {
    _LOG_TRACE (">> setInterestFilter");
    UniqueRecLock lock(m_mutex);
    if (!m_running || !m_connected)
      {
        return -1;
      }

    ccn_closure *interestClosure = new ccn_closure;
    
    // interestClosure->data = new ExecutorInterestClosure(interestCallback, m_executor);

    interestClosure->data = new tuple<Wrapper::InterestCallback *, Ptr<Executor> > (new InterestCallback (interestCallback), m_executor); // should be removed when closure is removed
    interestClosure->p = &incomingInterest;

    charbuf_stream prefixStream;
    wire::Ccnb::appendName (prefixStream, prefix);

    int ret = ccn_set_interest_filter (m_handle, prefixStream.buf ().getBuf (), interestClosure);
    if (ret < 0)
      {
        _LOG_ERROR ("<< setInterestFilter: ccn_set_interest_filter FAILED");
      }

    if (record)
      {
        m_registeredInterests.insert(pair<Name, InterestCallback>(prefix, interestCallback));
      }

    _LOG_TRACE ("<< setInterestFilter");

    return ret;
  }

  void
  Wrapper::clearInterestFilter (const Name &prefix, bool record/* = true*/)
  {
    _LOG_TRACE (">> clearInterestFilter");
    UniqueRecLock lock(m_mutex);
    if (!m_running || !m_connected)
      return;

    charbuf_stream prefixStream;
    wire::Ccnb::appendName (prefixStream, prefix);
    
    int ret = ccn_set_interest_filter (m_handle, prefixStream.buf ().getBuf (), 0);
    if (ret < 0)
      {
      }

    if (record)
      {
        m_registeredInterests.erase(prefix);
      }

    _LOG_TRACE ("<< clearInterestFilter");
  }

}//ndn
