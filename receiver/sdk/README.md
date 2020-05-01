# APSI SDK
## APSI

APSI is a fast Asymmetric Private Set Intersection library. With this SDK you can write your own applications that connect to an existing APSI service.

## Requirements
You will need the following libraries to build the SDK:

* [SEAL 3.2.0](https://github.com/microsoft/SEAL)
* [FourQlib](https://github.com/microsoft/FourQlib)
* [FLINT](http://flintlib.org)
    * [mpir](http://mpir.org)
    * [mpfr](http://mpfr.org)
    * [pthreads4w](https://sourceforge.net/projects/pthreads4w/)
* [GSL](https://github.com/Microsoft/GSL)
* [boost version 1.65.1](https://www.boost.org/)
* [log4cplus](https://github.com/log4cplus/log4cplus)
* [Crypto++ version 7](https://cryptopp.com)
* [ZeroMQ](http://zeromq.org)
    * [libzmq](https://github.com/zeromq/libzmq) - ZeroMQ base
    * [libzmqpp](https://github.com/zeromq/zmqpp) - ZeroMQ C++ wrapper

## Building the SDK in Windows
In Windows, you will need to:
* Get source code of the required libraries
* Build the following libraries (debug and release configurations)
    * SEAL as a static library
    * FLINT (and its mpir, mpfr and pthreads4w dependencies) as a dynamic library
    * boost
    * log4cplus as a static library
    * Crypto++ as a static library
    * ZeroMQ (the base and C++ wrapper libraries) as dynamic libraries

Once the code is compiled, please create a directory for the library include and binary files, for example `c:\APSILibraries`. Then you will need to arrange the files as follows:

```
c:\APSILibraries
   |_ boost-1.65.1
   |  |_ include
   |  \_ lib
   |_ cryptopp700
   |  |_ include
   |  \_ lib
   |     \_ x64
   |        |_ Debug
   |        \_ Release
   |_ flint2
   |  |_ include
   |  \_ lib
   |     \_ x64
   |        |_ Debug
   |        \_ Release
   |_ FourQlib
   |  |_ include
   |  \_ lib
   |     \_ x64
   |        |_ Debug
   |        \_ Release
   |_ GSL
   |  \_ include
   |_ libzmq
   |  |_ include
   |  \_ dll
   |     \_ x64
   |        |_ Debug
   |        \_ Release
   |_ libzmqpp
   |  |_ include
   |  \_ lib
   |     \_ x64
   |        |_ Debug
   |        \_ Release
   |_ log4cplus
   |  |_ include
   |  \_ lib
   |     \_ x64
   |        |_ Debug
   |        \_ Release
   |_ mpfr
   |  |_ include
   |  \_ lib
   |     \_ x64
   |        |_ Debug
   |        \_ Release
   |_ mpir
   |  |_ include
   |  \_ lib
   |     \_ x64
   |        |_ Debug
   |        \_ Release
   |_ pthreads4w
   |  |_ include
   |  \_ lib
   \_ SEAL
      |_ include
      \_ lib
         \_ x64
            |_ Debug
            \_ Release
```

You will need to create and environment variable called `APSILIBS`. The value of this environment variable should be the library directory, in the example above: `c:\APSILibraries`.

After setting the environment variable you should be able to open the SDK solution file and build the SDK. The result will be two binary files:
* APSINative.dll - Native library containing most of the APSI code
* APSIClient.dll - .Net Standard assembly that you can reference in your projects to connect to an APSI service