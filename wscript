# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION='0.6.0'

from waflib import Build, Logs, Utils, Task, TaskGen, Configure

def options(opt):
    opt.add_option('--debug',action='store_true',default=False,dest='debug',help='''debugging mode''')
    opt.add_option('--test', action='store_true',default=False,dest='_test',help='''build unit tests''')
    opt.add_option('--log4cxx', action='store_true',default=False,dest='log4cxx',help='''Compile with log4cxx logging support''')
    opt.add_option('--private_storage', dest='private_storage', default='opt', help='''simple for SimplePrivatekeyStorage; osx for OSXPrivatekeyStorage; opt for optimal one based on system (default)''')
    opt.add_option('--public_storage', dest='public_storage', default='opt', help='''basic for BasicIdentityStorage; opt for optimal one based on system (default)''')
    opt.add_option('--policy_manager', dest='policy_manager', default='opt', help='''none for NoVerifyPolicyManager; opt for optimal one based on system (default)''')
    opt.add_option('--encrypt_manager', dest='encrypt_manager', default='opt', help='''basic for BasicEncryptionManager; opt for optimal one based on system (default)''')

    opt.load('compiler_c compiler_cxx gnu_dirs c_osx')
    opt.load('boost doxygen ndnx cryptopp', tooldir=['waf-tools'])

def configure(conf):
    conf.load("compiler_c compiler_cxx boost ndnx gnu_dirs c_osx cryptopp")
    try:
        conf.load("doxygen")
    except:
        pass

    if conf.options.debug:
        conf.define ('_DEBUG', 1)
        conf.add_supported_cxxflags (cxxflags = ['-O0',
                                                 '-Wall',
                                                 '-Wno-unused-variable',
                                                 '-g3',
                                                 '-Wno-unused-private-field', # only clang supports
                                                 '-fcolor-diagnostics',       # only clang supports
                                                 '-Qunused-arguments',        # only clang supports
                                                 '-Wno-tautological-compare',    # suppress warnings from CryptoPP
                                                 ])
    else:
        conf.add_supported_cxxflags (cxxflags = ['-O3', '-g', '-Wno-tautological-compare'])

    if Utils.unversioned_sys_platform () == "darwin":
        conf.check_cxx(framework_name='CoreFoundation', uselib_store='OSX_COREFOUNDATION', mandatory=True, compile_filename='test.mm')
        conf.check_cxx(framework_name='CoreServices', uselib_store='OSX_CORESERVICES', mandatory=True, compile_filename='test.mm')
        conf.check_cxx(framework_name='Security',   uselib_store='OSX_SECURITY',   define_name='HAVE_SECURITY',
                       use="OSX_COREFOUNDATION", mandatory=True, compile_filename='test.mm')

    conf.check_security_parameter()
        
    conf.define ("NDN_CXX_VERSION", VERSION)

    conf.check_ndnx ()
    conf.check_openssl ()
    
    conf.check_cfg(package='libevent', args=['--cflags', '--libs'], uselib_store='LIBEVENT', mandatory=True)
    conf.check_cfg(package='libevent_pthreads', args=['--cflags', '--libs'], uselib_store='LIBEVENT_PTHREADS', mandatory=True)

    if conf.options.log4cxx:
        conf.check_cfg(package='liblog4cxx', args=['--cflags', '--libs'], uselib_store='LOG4CXX', mandatory=True)
        conf.define ("HAVE_LOG4CXX", 1)

    conf.check_cryptopp(path=conf.options.cryptopp_dir)

    conf.check_boost(lib='system test iostreams filesystem thread date_time regex program_options')

    boost_version = conf.env.BOOST_VERSION.split('_')
    if int(boost_version[0]) < 1 or int(boost_version[1]) < 46:
        Logs.error ("Minumum required boost version is 1.46")
        return

    if conf.options._test:
        conf.define ('_TESTS', 1)
        conf.env['TEST'] = 1

    conf.write_config_header('config.h')

def build (bld):

    sqlite3 = bld.objects(
        target = "SQLITE3",
        features = ["c"],
        cxxflags = "-fPIC",
        source = bld.path.ant_glob(['contrib/sqlite3/*.c']),
        )

    executor = bld.objects (
        target = "executor",
        features = ["cxx"],
        cxxflags = "-fPIC",
        source = bld.path.ant_glob(['executor/**/*.cc']),
        use = 'BOOST BOOST_THREAD LIBEVENT LIBEVENT_PTHREADS LOG4CXX',
        includes = ".",
        )

    scheduler = bld.objects (
        target = "scheduler",
        features = ["cxx"],
        cxxflags = "-fPIC",
        source = bld.path.ant_glob(['scheduler/**/*.cc']),
        use = 'BOOST BOOST_THREAD LIBEVENT LIBEVENT_PTHREADS LOG4CXX executor',
        includes = ".",
        )

    libndn_cxx = bld (
        target="ndn.cxx",
        features=['cxx', 'cxxshlib'],
        source = bld.path.ant_glob(['ndn.cxx/**/*.cpp', 'ndn.cxx/**/*.cc',
                                    'logging.cc',
                                    'libndn.cxx.pc.in']),
        use = 'CRYPTO BOOST BOOST_THREAD SSL NDNX LOG4CXX scheduler executor CRYPTOPP SQLITE3',
        includes = ". contrib/sqlite3",
        )

    if Utils.unversioned_sys_platform () == "darwin":
        libndn_cxx.mac_app = True
        libndn_cxx.source += bld.path.ant_glob (['ndn.cxx/**/*.mm', 'platforms/osx/**/*.mm'])
        libndn_cxx.use += " OSX_COREFOUNDATION OSX_SECURITY"

    # Unit tests
    if bld.env['TEST']:
      unittests = bld.program (
          target="unit-tests",
          features = "cxx cxxprogram",
          defines = "WAF",
          source = bld.path.ant_glob(['test/*.cc']),
          use = 'BOOST_TEST BOOST_FILESYSTEM BOOST_DATE_TIME BOOST_REGEX LOG4CXX ndn.cxx CRYPTOPP',
          includes = ".",
          install_prefix = None,
          )

    headers = bld.path.ant_glob(['ndn.cxx.h', 'ndn.cxx/**/*.h'])
    bld.install_files("%s" % bld.env['INCLUDEDIR'], headers, relative_trick=True)

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
    
@Configure.conf
def check_security_parameter(self):
    """
    Check the security parameters
    """
    if self.options.private_storage == 'simple':
        self.define ('USE_SIMPLE_PRIVATEKEY_STORAGE', 1)
    elif self.options.private_storage == 'osx':
        self.define ('USE_OSX_PRIVATEKEY_STORAGE', 1)
    else:
        if Utils.unversioned_sys_platform () == "darwin":
            self.define ('USE_OSX_PRIVATEKEY_STORAGE', 1)
        else:
            self.define ('USE_SIMPLE_PRIVATEKEY_STORAGE', 1)

    if self.options.public_storage == 'basic':
        self.define ('USE_BASIC_IDENTITY_STORAGE', 1)
    else:
        self.define ('USE_BASIC_IDENTITY_STORAGE', 1)

    if self.options.policy_manager == 'none':
        self.define ('USE_NO_VERIFY_POLICY_MANAGER', 1)
    else:
        self.define ('USE_SIMPLE_POLICY_MANAGER', 1)

    if self.options.encrypt_manager == 'basic':
        self.define ('USE_BASIC_ENCRYPTION_MANAGER', 1)
    else:
        self.define ('USE_BASIC_ENCRYPTION_MANAGER', 1)
        


# doxygen docs
from waflib.Build import BuildContext
class doxy (BuildContext):
    cmd = "doxygen"
    fun = "doxygen"

def doxygen (bld):
    if not bld.env.DOXYGEN:
        bld.fatal ("ERROR: cannot build documentation (`doxygen' is not found in $PATH)")
    bld (features="doxygen",
         doxyfile='doc/doxygen.conf')

# doxygen docs
from waflib.Build import BuildContext
class sphinx (BuildContext):
    cmd = "sphinx"
    fun = "sphinx"

def sphinx (bld):
    bld.load('sphinx_build', tooldir=['waf-tools'])

    bld (features="sphinx",
         outdir = "doc/html",
         source = "doc/source/conf.py")


@TaskGen.extension('.mm')
def mm_hook(self, node):
    """Alias .mm files to be compiled the same as .cc files, gcc will do the right thing."""
    return self.create_compiled_task('cxx', node)
