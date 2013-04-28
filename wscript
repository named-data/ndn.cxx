# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION='0.5.0'

from waflib import Build, Logs, Utils, Task, TaskGen, Configure

def options(opt):
    opt.add_option('--debug',action='store_true',default=False,dest='debug',help='''debugging mode''')
    opt.add_option('--test', action='store_true',default=False,dest='_test',help='''build unit tests''')
    opt.add_option('--log4cxx', action='store_true',default=False,dest='log4cxx',help='''Compile with log4cxx logging support''')

    opt.load('compiler_c compiler_cxx boost ccnx')
    opt.load('tinyxml', tooldir=['waf-tools'])
    opt.load('gnu_dirs')

def configure(conf):
    conf.load("compiler_c compiler_cxx")

    if conf.options.debug:
        conf.define ('_DEBUG', 1)
        conf.add_supported_cxxflags (cxxflags = ['-O0',
                                                 '-Wall',
                                                 '-Wno-unused-variable',
                                                 '-g3',
                                                 '-Wno-unused-private-field', # only clang supports
                                                 '-fcolor-diagnostics',       # only clang supports
                                                 '-Qunused-arguments'         # only clang supports
                                                 ])
    else:
        conf.add_supported_cxxflags (cxxflags = ['-O3', '-g'])

    conf.define ("CCNX_CPP_VERSION", VERSION)

    conf.check_cfg(package='libevent', args=['--cflags', '--libs'], uselib_store='LIBEVENT', mandatory=True)
    conf.check_cfg(package='libevent_pthreads', args=['--cflags', '--libs'], uselib_store='LIBEVENT_PTHREADS', mandatory=True)

    if not conf.check_cfg(package='openssl', args=['--cflags', '--libs'], uselib_store='SSL', mandatory=False):
        libcrypto = conf.check_cc(lib='crypto',
                                  header_name='openssl/crypto.h',
                                  define_name='HAVE_SSL',
                                  uselib_store='SSL')
    else:
        conf.define ("HAVE_SSL", 1)
    if not conf.get_define ("HAVE_SSL"):
        conf.fatal ("Cannot find SSL libraries")

    if conf.options.log4cxx:
        conf.check_cfg(package='liblog4cxx', args=['--cflags', '--libs'], uselib_store='LOG4CXX', mandatory=True)
        conf.define ("HAVE_LOG4CXX", 1)

    conf.load('tinyxml')
    conf.check_tinyxml(path=conf.options.tinyxml_dir)

    conf.load ('ccnx')

    conf.load('boost')

    conf.load('gnu_dirs')
    conf.check_boost(lib='system test iostreams filesystem thread date_time')

    boost_version = conf.env.BOOST_VERSION.split('_')
    if int(boost_version[0]) < 1 or int(boost_version[1]) < 46:
        Logs.error ("Minumum required boost version is 1.46")
        return

    conf.check_ccnx (path=conf.options.ccnx_dir)
    conf.define ('CCNX_PATH', conf.env.CCNX_ROOT)

    if conf.options._test:
        conf.define ('_TESTS', 1)
        conf.env.TEST = 1

    conf.write_config_header('config.h')

def build (bld):
    executor = bld.objects (
        target = "executor",
        features = ["cxx"],
        source = bld.path.ant_glob(['executor/**/*.cc']),
        use = 'BOOST BOOST_THREAD LIBEVENT LIBEVENT_PTHREADS LOG4CXX',
        includes = ".",
        )

    scheduler = bld.objects (
        target = "scheduler",
        features = ["cxx"],
        source = bld.path.ant_glob(['scheduler/**/*.cc']),
        use = 'BOOST BOOST_THREAD LIBEVENT LIBEVENT_PTHREADS LOG4CXX executor',
        includes = ".",
        )

    libccnx = bld (
        target="ccnx-cpp",
        features=['cxx', 'cxxshlib'],
        source = bld.path.ant_glob(['ccnx-cpp/**/*.cpp']),
        use = 'TINYXML BOOST BOOST_THREAD SSL CCNX LOG4CXX scheduler executor',
        includes = ".",
        )

    # Unit tests
    if bld.env['TEST']:
      unittests = bld.program (
          target="unit-tests",
          features = "cxx cxxprogram",
          defines = "WAF",
          source = bld.path.ant_glob(['test/*.cc']),
          use = 'BOOST_TEST BOOST_FILESYSTEM BOOST_DATE_TIME LOG4CXX ccnx-cpp',
          includes = ".",
          install_prefix = None,
          )

    headers = bld.path.ant_glob(['ccnx-cpp.h', 'ccnx-cpp/*.h'])
    bld.install_files("%s" % bld.env['INCLUDEDIR'], headers, relative_trick=True)

    pc = bld (
        features = "subst",
        source = 'libccnx-cpp.pc.in',
        target= 'libccnx-cpp.pc',
        install_path = '${LIBDIR}/pkgconfig',
        PREFIX = bld.env['PREFIX'],
        INCLUDEDIR = '%s/ccnx-cpp' % bld.env['INCLUDEDIR'],
        VERSION = VERSION,
        )

@Configure.conf
def add_supported_cxxflags(self, cxxflags):
    """
    Check which cxxflags are supported by compiler and add them to env.CXXFLAGS variable
    """
    self.start_msg('Checking allowed flags for c++ compiler')

    supportedFlags = []
    for flag in cxxflags:
        if self.check_cxx (cxxflags=[flag], mandatory=False):
            supportedFlags += [flag]

    self.end_msg (' '.join (supportedFlags))
    self.env.CXXFLAGS += supportedFlags
