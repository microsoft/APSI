# APSI Library

Fast asymmetric PSI library

## Requirements

* [SEAL 3.2.0](https://github.com/microsoft/SEAL)
* [FourQlib](https://github.com/kiromaru/FourQlib)
* [FLINT](http://flintlib.org)
    * [mpir](http://mpir.org)
    * [mpfr](http://mpfr.org)
    * [pthreads4w](https://sourceforge.net/projects/pthreads4w/)
* [GSL](https://github.com/Microsoft/GSL)
* [boost 1.65.1](https://www.boost.org/)
* [log4cplus](https://github.com/log4cplus/log4cplus)
* [Crypto++ v7](https://cryptopp.com) - Ubuntu 18.04 installs version 6 by default, version 7 is needed in order to correctly support C++17.
* [ZeroMQ](http://zeromq.org)
    * [libzmq](https://github.com/zeromq/libzmq) - ZeroMQ base
    * [libzmqpp](https://github.com/zeromq/zmqpp) - ZeroMQ C++ wrapper

### Additional requirements
* [Google Test](https://github.com/google/googletest) - For unit tests and integration tests projects
* [TCLAP](https://sourceforge.net/projects/tclap/) - Command line parser for stand alone executables (Receiver / Sender)
