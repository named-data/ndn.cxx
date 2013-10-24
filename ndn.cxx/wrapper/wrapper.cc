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


#define ndn ndn_client
extern "C" {
#include <ndn/fetch.h>
}
#undef ndn

#include <poll.h>
#include <boost/throw_exception.hpp>
#include <boost/random.hpp>
#include <boost/make_shared.hpp>
#include <boost/algorithm/string.hpp>

#include "charbuf.h"

#include <sstream>

#include "executor/executor.h"

#include "logging.h"
#include "ndn.cxx/wire/ndnb.h"

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
  Wrapper::connectNdnd()
  {
    if (m_handle != 0) {
      ndn_disconnect (m_handle);
      //ndn_destroy (&m_handle);
    }
    else
      {
        m_handle = ndn_create ();
      }

    UniqueRecLock lock(m_mutex);
    if (ndn_connect(m_handle, NULL) < 0)
      {
        BOOST_THROW_EXCEPTION (Error::ndnOperation() << errmsg_info_str("connection to ndnd failed"));
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
    connectNdnd();
    m_thread = thread (&Wrapper::ndnLoop, this);
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

        ndn_disconnect (m_handle);
      //ndn_destroy (&m_handle);
        m_connected = false;
      }
  }

  void
  Wrapper::ndnLoop ()
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
              res = ndn_run (m_handle, 0);
            }

            if (!m_running) break;
            
            if (res < 0) {
              _LOG_ERROR ("ndn_run returned negative status: " << res);
              
              BOOST_THROW_EXCEPTION (Error::ndnOperation()
                                     << errmsg_info_str("ndn_run returned error"));
            }


            pollfd pfds[1];
            {
              UniqueRecLock lock(m_mutex);

              pfds[0].fd = ndn_get_connection_fd (m_handle);
              pfds[0].events = POLLIN;
              if (ndn_output_is_pending (m_handle))
                pfds[0].events |= POLLOUT;
            }

            int ret = poll (pfds, 1, 1);
            if (ret < 0)
              {
                BOOST_THROW_EXCEPTION (Error::ndnOperation() << errmsg_info_str("ndnd socket failed (probably ndnd got stopped)"));
              }
          }
        catch (Error::ndnOperation &e)
          {
            m_connected = false;
            // probably ndnd has been stopped
            // try reconnect with sleep
            int interval = 1;
            int maxInterval = 32;
            while (m_running)
              {
                try
                  {
                    this_thread::sleep (boost::get_system_time () +  time::Seconds (interval) + time::Milliseconds (rangeUniformRandom ()));

                    connectNdnd ();
                    _LOG_DEBUG("reconnect to ndnd succeeded");
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
  Wrapper::putToNdnd (const Blob & dataBlob)
  {
    _LOG_TRACE (">> putToNdnd");
    UniqueRecLock lock(m_mutex);
    if (!m_running || !m_connected)
      {
        _LOG_TRACE ("<< not running or connected");
        return -1;
      }


    if (ndn_put(m_handle, dataBlob.buf(), dataBlob.size()) < 0)
      {
        _LOG_ERROR ("ndn_put failed");
        // BOOST_THROW_EXCEPTION(Error::ndnOperation() << errmsg_info_str("ndnput failed"));
      }
    else
      {
        _LOG_DEBUG ("<< putToNdnd");
      }

    return 0;
  }

  int 
  Wrapper::publishDataByCert (Data &data, const Name & certificateName)
  {
    _LOG_TRACE("publishDataByCert: " << data.getName ());
    m_keychain->sign(data, certificateName);
    return putToNdnd(*data.encodeToWire());
  }

  int 
  Wrapper::publishDataByIdentity (Data &data, const Name &identityName)
  {
    _LOG_TRACE("publishDataByCert: " << data.getName ());
    m_keychain->signByIdentity(data, identityName);
    return putToNdnd(*data.encodeToWire());
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

  static ndn_upcall_res
  incomingInterest(ndn_closure *selfp,
                   ndn_upcall_kind kind,
                   ndn_upcall_info *info)
  {
    Wrapper::InterestCallback *f;
    Ptr<Executor> executor;
    tuple<Wrapper::InterestCallback *, Ptr<Executor> > *realData = reinterpret_cast< tuple<Wrapper::InterestCallback *, Ptr<Executor> > * > (selfp->data);
    tie (f, executor) = *realData;

    switch (kind)
      {
      case NDN_UPCALL_FINAL: // effective in unit tests
        // delete closure;
        executor->execute (bind (deleteInInterestTuple, realData));

        delete selfp;
        _LOG_TRACE ("<< incomingInterest with NDN_UPCALL_FINAL");
        return NDN_UPCALL_RESULT_OK;

      case NDN_UPCALL_INTEREST:
        _LOG_TRACE (">> incomingInterest upcall: " << Name(info->interest_ndnb, info->interest_comps));
        break;

      default:
        _LOG_TRACE ("<< incomingInterest with NDN_UPCALL_RESULT_OK: " << Name(info->interest_ndnb, info->interest_comps));
        return NDN_UPCALL_RESULT_OK;
      }

    Ptr<Interest> interest = Ptr<Interest>( new Interest(info->pi));
    interest->setName (Name (info->interest_ndnb, info->interest_comps));

    executor->execute (bind (*f, interest));
    // this will be run in executor
    // (*f) (interest);
    // closure->runInterestCallback(interest);

    return NDN_UPCALL_RESULT_OK;
  }

  static void
  deleteInDataTuple (tuple<Ptr<Closure>, Ptr<Executor>, Ptr<Interest>, Ptr<security::Keychain> > *tuple)
  {
    // delete tuple->get<0> ();
    delete tuple;
  }

  static void
  onVerify(const DataCallback & dataCallback, Ptr<Data> data, Ptr<Executor> executor)
  {
    executor->execute (bind (dataCallback, data));
  }

  static void
  onVerifyError(const UnverifiedCallback & unverifiedCallback, Ptr<Data> data, Ptr<Executor> executor)
  {
    executor->execute (bind (unverifiedCallback, data));
  }

  static ndn_upcall_res
  incomingData(ndn_closure *selfp,
               ndn_upcall_kind kind,
               ndn_upcall_info *info)
  {
    // Closure *cp = static_cast<Closure *> (selfp->data);
    Ptr<Closure> cp;
    Ptr<Executor> executor;
    Ptr<Interest> interest;
    Ptr<security::Keychain> keychain;
    tuple<Ptr<Closure>, 
          Ptr<Executor>, 
          Ptr<Interest>, 
          Ptr<security::Keychain> > *realData = reinterpret_cast< tuple<Ptr<Closure>, 
                                                                        Ptr<Executor>,
                                                                        Ptr<Interest>, 
                                                                        Ptr<security::Keychain> > * > (selfp->data);
  tie (cp, executor, interest, keychain) = *realData;

    switch (kind)
      {
      case NDN_UPCALL_FINAL:  // effecitve in unit tests
        executor->execute (bind (deleteInDataTuple, realData));

        cp = NULL;
        delete selfp;
        _LOG_TRACE ("<< incomingData with NDN_UPCALL_FINAL");
        return NDN_UPCALL_RESULT_OK;

      case NDN_UPCALL_CONTENT:
        _LOG_TRACE (">> incomingData content upcall: " << Name (info->content_ndnb, info->content_comps));
        break;

        // this is the case where the intentionally unsigned packets coming (in Encapsulation case)
      case NDN_UPCALL_CONTENT_BAD:
        _LOG_TRACE (">> incomingData content bad upcall: " << Name (info->content_ndnb, info->content_comps));
        break;

        // always ask ndnd to try to fetch the key
      case NDN_UPCALL_CONTENT_UNVERIFIED:
        _LOG_TRACE (">> incomingData content unverified upcall: " << Name (info->content_ndnb, info->content_comps));
        break;

      case NDN_UPCALL_INTEREST_TIMED_OUT: {
        if (cp != NULL)
          {
            Name interestName (info->interest_ndnb, info->interest_comps);
            _LOG_TRACE ("<< incomingData timeout: " << Name (info->interest_ndnb, info->interest_comps));
            executor->execute (bind (cp->m_timeoutCallback, cp, interest));
          }
        else
          {
            _LOG_TRACE ("<< incomingData timeout, but callback is not set...: " << Name (info->interest_ndnb, info->interest_comps));
          }
        return NDN_UPCALL_RESULT_OK;
      }
      default:
        _LOG_TRACE(">> unknown upcall type");
        return NDN_UPCALL_RESULT_OK;
      }

    Ptr<Blob> blob = Ptr<Blob> (new Blob(info->content_ndnb, info->pco->offset[NDN_PCO_E]));
    Ptr<Data> data = Data::decodeFromWire(blob);


    keychain->verifyData(data, 
                           boost::bind(onVerify, cp->m_dataCallback, _1, executor),
                           boost::bind(onVerifyError, cp->m_unverifiedCallback, _1, executor),
                           cp->m_stepCount);
 
   _LOG_TRACE (">> incomingData");
    
    return NDN_UPCALL_RESULT_OK;
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
    
    ndn_closure *dataClosure = new ndn_closure;
    
    // Closure *myClosure = new ExecutorClosure(closure, m_executor);
    Ptr<Closure> myClosure = Ptr<Closure>(new Closure(*closurePtr));
    dataClosure->data = new tuple<Ptr<Closure>, Ptr<Executor>, Ptr<Interest>, Ptr<security::Keychain> > (myClosure, m_executor, interestPtr, m_keychain);
    
    dataClosure->p = &incomingData;
    
    UniqueRecLock lock(m_mutex);

    charbuf_stream nameStream;
    wire::Ndnb::appendName (nameStream, interestPtr->getName ());
  
    charbuf_stream interestStream;
    wire::Ndnb::appendInterest (interestStream, *interestPtr);

    if (ndn_express_interest (m_handle, nameStream.buf ().getBuf (),
                              dataClosure,
                              interestStream.buf ().getBuf ()
                              ) < 0)
      {
        _LOG_ERROR ("<< sendInterest: ndn_express_interest FAILED!!!");
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

    ndn_closure *interestClosure = new ndn_closure;
    
    // interestClosure->data = new ExecutorInterestClosure(interestCallback, m_executor);

    interestClosure->data = new tuple<Wrapper::InterestCallback *, Ptr<Executor> > (new InterestCallback (interestCallback), m_executor); // should be removed when closure is removed
    interestClosure->p = &incomingInterest;

    charbuf_stream prefixStream;
    wire::Ndnb::appendName (prefixStream, prefix);

    int ret = ndn_set_interest_filter (m_handle, prefixStream.buf ().getBuf (), interestClosure);
    if (ret < 0)
      {
        _LOG_ERROR ("<< setInterestFilter: ndn_set_interest_filter FAILED");
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
    wire::Ndnb::appendName (prefixStream, prefix);
    
    int ret = ndn_set_interest_filter (m_handle, prefixStream.buf ().getBuf (), 0);
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
