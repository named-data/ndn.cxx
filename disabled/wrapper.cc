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

#include "wrapper.h"

extern "C" {
#include <ndn/fetch.h>
}
#include <poll.h>
#include <boost/throw_exception.hpp>
#include <boost/random.hpp>
#include <boost/make_shared.hpp>
#include <boost/algorithm/string.hpp>

#include <sstream>

// #include "ndn.cxx/verifier.h"
#include "executor/executor.h"

#include "logging.h"
#include "ndn.cxx/wire/ndnb.h"


INIT_LOGGER ("ndn.Wrapper");

typedef boost::error_info<struct tag_errmsg, std::string> errmsg_info_str;
typedef boost::error_info<struct tag_errmsg, int> errmsg_info_int;

using namespace std;
using namespace boost;

namespace ndn {

// hack to enable fake signatures
// min length for signature field is 16, as defined in ndn_buf_decoder.c:728
const int DEFAULT_SIGNATURE_SIZE = 16;

// Although ndn_buf_decoder.c:745 defines minimum length 16, something else is checking and only 32-byte fake value is accepted by ndnd
const int PUBLISHER_KEY_SIZE = 32;

static int
ndn_encode_garbage_Signature(struct ndn_charbuf *buf)
{
    int res = 0;

    res |= ndn_charbuf_append_tt(buf, NDN_DTAG_Signature, NDN_DTAG);

    // Let's cheat more.  Default signing algorithm in ndnd is SHA256, so we just need add 32 bytes of garbage
    static char garbage [DEFAULT_SIGNATURE_SIZE];

    // digest and witness fields are optional, so use default ones

    res |= ndn_charbuf_append_tt(buf, NDN_DTAG_SignatureBits, NDN_DTAG);
    res |= ndn_charbuf_append_tt(buf, DEFAULT_SIGNATURE_SIZE, NDN_BLOB);
    res |= ndn_charbuf_append(buf, garbage, DEFAULT_SIGNATURE_SIZE);
    res |= ndn_charbuf_append_closer(buf);

    res |= ndn_charbuf_append_closer(buf);

    return(res == 0 ? 0 : -1);
}

static int
ndn_pack_unsigned_ContentObject(struct ndn_charbuf *buf,
                                const struct ndn_charbuf *Name,
                                const struct ndn_charbuf *SignedInfo,
                                const void *data,
                                size_t size)
{
    int res = 0;
    struct ndn_charbuf *content_header;
    size_t closer_start;

    content_header = ndn_charbuf_create();
    res |= ndn_charbuf_append_tt(content_header, NDN_DTAG_Content, NDN_DTAG);
    if (size != 0)
        res |= ndn_charbuf_append_tt(content_header, size, NDN_BLOB);
    closer_start = content_header->length;
    res |= ndn_charbuf_append_closer(content_header);
    if (res < 0)
        return(-1);

    res |= ndn_charbuf_append_tt(buf, NDN_DTAG_ContentObject, NDN_DTAG);

    res |= ndn_encode_garbage_Signature(buf);

    res |= ndn_charbuf_append_charbuf(buf, Name);
    res |= ndn_charbuf_append_charbuf(buf, SignedInfo);
    res |= ndnb_append_tagged_blob(buf, NDN_DTAG_Content, data, size);
    res |= ndn_charbuf_append_closer(buf);

    ndn_charbuf_destroy(&content_header);
    return(res == 0 ? 0 : -1);
}

Wrapper::Wrapper()
  : m_handle (0)
  , m_running (true)
  , m_connected (false)
  , m_executor (new Executor(1))
  // , m_verifier(new Verifier(this))
{
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

Bytes
Wrapper::createContentObject(const Name  &name, const void *buf, size_t len, int freshness, const Name &keyNameParam)
{
  {
    UniqueRecLock lock(m_mutex);
    if (!m_running || !m_connected)
      {
        _LOG_TRACE ("<< not running or connected");
        return Bytes ();
      }
  }

  ndn_charbuf *content = ndn_charbuf_create();

  struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
  sp.freshness = freshness;

  Name keyName;

  if (keyNameParam.size() == 0)
  {
    // use default key name
    CharbufPtr defaultKeyNamePtr = boost::make_shared<Charbuf>();
    ndn_get_public_key_and_name(m_handle, &sp, NULL, NULL, defaultKeyNamePtr->getBuf());
    keyName = Name(*defaultKeyNamePtr);

    _LOG_DEBUG ("DEFAULT KEY NAME: " << keyName);
  }
  else
  {
    keyName = keyNameParam;
  }

  if (sp.template_ndnb == NULL)
  {
    sp.template_ndnb = ndn_charbuf_create();
    ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_SignedInfo, NDN_DTAG);
  }
  // no idea what the following 3 lines do, but it was there
  else if (sp.template_ndnb->length > 0) {
      sp.template_ndnb->length--;
  }
  ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_KeyLocator, NDN_DTAG);
  ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_KeyName, NDN_DTAG);

  charbuf_stream keyStream;
  wire::Ndnb::appendName (keyStream, keyName);
  
  ndn_charbuf_append(sp.template_ndnb, keyStream.buf ().getBuf ()->buf, keyStream.buf ().getBuf ()->length);
  ndn_charbuf_append_closer(sp.template_ndnb); // </KeyName>
  ndn_charbuf_append_closer(sp.template_ndnb); // </KeyLocator>
  sp.sp_flags |= NDN_SP_TEMPL_KEY_LOCATOR;
  ndn_charbuf_append_closer(sp.template_ndnb); // </SignedInfo>

  charbuf_stream nameStream;
  wire::Ndnb::appendName (nameStream, name);
  
  if (ndn_sign_content(m_handle, content, nameStream.buf ().getBuf (), &sp, buf, len) != 0)
  {
    BOOST_THROW_EXCEPTION(Error::ndnOperation() << errmsg_info_str("sign content failed"));
  }

  Bytes bytes;
  readRaw(bytes, content->buf, content->length);

  ndn_charbuf_destroy (&content);
  if (sp.template_ndnb != NULL)
  {
    ndn_charbuf_destroy (&sp.template_ndnb);
  }

  return bytes;
}

int
Wrapper::putToNdnd (const Bytes &contentObject)
{
  _LOG_TRACE (">> putToNdnd");
  UniqueRecLock lock(m_mutex);
  if (!m_running || !m_connected)
    {
      _LOG_TRACE ("<< not running or connected");
      return -1;
    }


  if (ndn_put(m_handle, head(contentObject), contentObject.size()) < 0)
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
Wrapper::publishData (const Name &name, const unsigned char *buf, size_t len, int freshness, const Name &keyName)
{
  _LOG_TRACE ("publishData: " << name);
  Bytes co = createContentObject(name, buf, len, freshness, keyName);
  return putToNdnd(co);
}

int
Wrapper::publishUnsignedData(const Name &name, const unsigned char *buf, size_t len, int freshness)
{
  _LOG_TRACE ("publishUnsignedData: " << name);
  {
    UniqueRecLock lock(m_mutex);
    if (!m_running || !m_connected)
      {
        _LOG_TRACE ("<< not running or connected");
        return -1;
      }
  }

  ndn_charbuf *content = ndn_charbuf_create();
  ndn_charbuf *signed_info = ndn_charbuf_create();

  static char fakeKey[PUBLISHER_KEY_SIZE];

  int res = ndn_signed_info_create(signed_info,
                                   fakeKey, PUBLISHER_KEY_SIZE,
                                   NULL,
                                   NDN_CONTENT_DATA,
                                   freshness,
                                   NULL,
                                   NULL  // ndnd is happy with absent key locator and key itself... ha ha
                                   );

  charbuf_stream nameStream;
  wire::Ndnb::appendName (nameStream, name);

  ndn_pack_unsigned_ContentObject(content, nameStream.buf ().getBuf (), signed_info, buf, len);

  Bytes bytes;
  readRaw(bytes, content->buf, content->length);

  ndn_charbuf_destroy (&content);
  ndn_charbuf_destroy (&signed_info);

  return putToNdnd (bytes);
}


static void
deleterInInterestTuple (tuple<Wrapper::InterestCallback *, ExecutorPtr> *tuple)
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
  ExecutorPtr executor;
  tuple<Wrapper::InterestCallback *, ExecutorPtr> *realData = reinterpret_cast< tuple<Wrapper::InterestCallback *, ExecutorPtr>* > (selfp->data);
  tie (f, executor) = *realData;

  switch (kind)
    {
    case NDN_UPCALL_FINAL: // effective in unit tests
      // delete closure;
      executor->execute (bind (deleterInInterestTuple, realData));

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

  InterestPtr interest = make_shared<Interest> (info->pi);
  interest->setName (Name (info->interest_ndnb, info->interest_comps));

  executor->execute (bind (*f, interest));
  // this will be run in executor
  // (*f) (interest);
  // closure->runInterestCallback(interest);

  return NDN_UPCALL_RESULT_OK;
}

static void
deleterInDataTuple (tuple<Closure *, ExecutorPtr, InterestPtr> *tuple)
{
  delete tuple->get<0> ();
  delete tuple;
}

static ndn_upcall_res
incomingData(ndn_closure *selfp,
             ndn_upcall_kind kind,
             ndn_upcall_info *info)
{
  // Closure *cp = static_cast<Closure *> (selfp->data);
  Closure *cp;
  ExecutorPtr executor;
  InterestPtr interest;
  tuple<Closure *, ExecutorPtr, InterestPtr> *realData = reinterpret_cast< tuple<Closure*, ExecutorPtr, InterestPtr>* > (selfp->data);
  tie (cp, executor, interest) = *realData;

  switch (kind)
    {
    case NDN_UPCALL_FINAL:  // effecitve in unit tests
      executor->execute (bind (deleterInDataTuple, realData));

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
        executor->execute (bind (&Closure::runTimeoutCallback, cp, interestName, *cp, interest));
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

  PcoPtr pco = make_shared<ParsedContentObject> (info->content_ndnb, info->pco->offset[NDN_PCO_E]);

  // this will be run in executor
  executor->execute (bind (&Closure::runDataCallback, cp, pco->name (), pco));
  _LOG_TRACE (">> incomingData");

  return NDN_UPCALL_RESULT_OK;
}

int Wrapper::sendInterest (const Interest &interest, const Closure &closure)
{
  _LOG_TRACE (">> sendInterest: " << interest.getName ());
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
  Closure *myClosure = closure.dup ();
  dataClosure->data = new tuple<Closure*, ExecutorPtr, InterestPtr> (myClosure, m_executor, make_shared<Interest> (interest));

  dataClosure->p = &incomingData;

  UniqueRecLock lock(m_mutex);

  charbuf_stream nameStream;
  wire::Ndnb::appendName (nameStream, interest.getName ());

  charbuf_stream interestStream;
  wire::Ndnb::appendInterest (interestStream, interest);

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

  interestClosure->data = new tuple<Wrapper::InterestCallback *, ExecutorPtr> (new InterestCallback (interestCallback), m_executor); // should be removed when closure is removed
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

Name
Wrapper::getLocalPrefix ()
{
  struct ndn * tmp_handle = ndn_create ();
  int res = ndn_connect (tmp_handle, NULL);
  if (res < 0)
    {
      return Name();
    }

  string retval = "";

  struct ndn_charbuf *templ = ndn_charbuf_create();
  ndn_charbuf_append_tt(templ, NDN_DTAG_Interest, NDN_DTAG);
  ndn_charbuf_append_tt(templ, NDN_DTAG_Name, NDN_DTAG);
  ndn_charbuf_append_closer(templ); /* </Name> */
  // XXX - use pubid if possible
  ndn_charbuf_append_tt(templ, NDN_DTAG_MaxSuffixComponents, NDN_DTAG);
  ndnb_append_number(templ, 1);
  ndn_charbuf_append_closer(templ); /* </MaxSuffixComponents> */
  ndnb_tagged_putf(templ, NDN_DTAG_Scope, "%d", 2);
  ndn_charbuf_append_closer(templ); /* </Interest> */

  struct ndn_charbuf *name = ndn_charbuf_create ();
  res = ndn_name_from_uri (name, "/local/ndn/prefix");
  if (res < 0) {
  }
  else
    {
      struct ndn_fetch *fetch = ndn_fetch_new (tmp_handle);

      struct ndn_fetch_stream *stream = ndn_fetch_open (fetch, name, "/local/ndn/prefix",
                                                        NULL, 4, NDN_V_HIGHEST, 0);
      if (stream == NULL) {
      }
      else
        {
          ostringstream os;

          int counter = 0;
          char buf[256];
          while (true) {
            res = ndn_fetch_read (stream, buf, sizeof(buf));

            if (res == 0) {
              break;
            }

            if (res > 0) {
              os << string(buf, res);
            } else if (res == NDN_FETCH_READ_NONE) {
              if (counter < 2)
                {
                  ndn_run(tmp_handle, 1000);
                  counter ++;
                }
              else
                {
                  break;
                }
            } else if (res == NDN_FETCH_READ_END) {
              break;
            } else if (res == NDN_FETCH_READ_TIMEOUT) {
              break;
            } else {
              break;
            }
          }
          retval = os.str ();
          stream = ndn_fetch_close(stream);
        }
      fetch = ndn_fetch_destroy(fetch);
    }

  ndn_charbuf_destroy (&name);

  ndn_disconnect (tmp_handle);
  ndn_destroy (&tmp_handle);

  boost::algorithm::trim(retval);
  return Name(retval);
}

bool
Wrapper::verify(PcoPtr &pco, double maxWait)
{
  return true; // totally fake
  // return m_verifier->verify(pco, maxWait);
}

/// @cond include_hidden
// This is needed just for get function implementation
struct GetState
{
  GetState (double maxWait)
  {
    double intPart, fraction;
    fraction = modf (std::abs(maxWait), &intPart);

    m_maxWait = time::Now ()
      + time::Seconds (intPart)
      + time::Microseconds (fraction * 1000000);
  }

  PcoPtr
  WaitForResult ()
  {
    //_LOG_TRACE("GetState::WaitForResult start");
    boost::unique_lock<boost::mutex> lock (m_mutex);
    m_cond.timed_wait (lock, m_maxWait);
    //_LOG_TRACE("GetState::WaitForResult finish");

    return m_retval;
  }

  void
  DataCallback (Name name, PcoPtr pco)
  {
    //_LOG_TRACE("GetState::DataCallback, Name [" << name << "]");
    boost::unique_lock<boost::mutex> lock (m_mutex);
    m_retval = pco;
    m_cond.notify_one ();
  }

  void
  TimeoutCallback (Name name)
  {
    boost::unique_lock<boost::mutex> lock (m_mutex);
    m_cond.notify_one ();
  }

private:
  Time m_maxWait;

  boost::mutex m_mutex;
  boost::condition_variable    m_cond;

  PcoPtr  m_retval;
};
/// @endcond

PcoPtr
Wrapper::get(const Interest &interest, double maxWait/* = 4.0*/)
{
  _LOG_TRACE (">> get: " << interest.getName ());
  {
    UniqueRecLock lock(m_mutex);
    if (!m_running || !m_connected)
      {
        _LOG_ERROR ("<< get: not running or connected");
        return PcoPtr ();
      }
  }

  GetState state (maxWait);
  this->sendInterest (interest, Closure (boost::bind (&GetState::DataCallback, &state, _1, _2),
                                         boost::bind (&GetState::TimeoutCallback, &state, _1)));
  return state.WaitForResult ();
}

}
