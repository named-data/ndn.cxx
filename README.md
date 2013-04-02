ccnx-cpp: C++ API for CCNx C Library
====================================

People often feel confusing and tedious when using CCNx C library, and this is an attempt to make it easier to program NDN applications using C++.

This API remotely resembles PyCCN API if you by any chance have already got yourself familiar with that.

The functions included are be roughly devided into two categories: ccnx operations and async operations.

1. CCNx Operations
------------------
This is a set of functions that provide relative easier ways to perform CCNx operations, including manipulating ccnx names, content objects, interests, sending interests, callbacks (closure) for content objects, name prefix discovery, signature verifications, etc.. There is also a blocking API to fetch content object.

2. Async Operations
-------------------
Communications in ccnx is mostly async. There is an event thread running ccnx and processing the ccnx events (e.g. interests received, expired, content received, etc..). As such, you don't really want to do a lot of processing in the ccnx event thread (which blocks processing of that events). Hence we provide a simple executor API, which allows you to process the events in separate threads. We also provide a scheduler which allows you to scheduler various events as you wish. The scheduler is based on libevent C API.

3. Build and Install
--------------------
To see more options, use `./waf configure --help`.
For default install, use
```bash
./waf configure
./waf
sudo ./waf install
```

### If you're using Mac OS X, Macport's g++ is not recommended. It may cause mysterious memory error with tinyxml. Use clang++ or Apple's g++ instead.

Normally, default install goes to /usr/local.
If you have added /usr/local/lib/pkgconfig to your `PKG_CONFIG_PATH`, then you can compile your code like this:
```bash
g++ code.cpp `pkg-config --cflags --libs libccnx-cpp`
```

4. Examples
-----------
You can find examples in /test directory, which could be a starting point.
There is also extensive usage of this library in [ChronoShare](https://github.com/named-data/ChronoShare).


