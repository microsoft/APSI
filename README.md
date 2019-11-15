# APSI Library

Fast asymmetric PSI library

## Requirements in order

1. [Microsoft GSL](https://github.com/Microsoft/GSL)
    - Linux: `sudo apt install libmsgsl-dev`
1. [ZLIB](https://github.com/madler/zlib)
    - Linux: `sudo apt install zlib1g-dev`
1. [Microosft SEAL 3.4.4](https://github.com/microsoft/SEAL)
    - Linux: `cmake -DSEAL_USE_MSGSL=on -DSEAL_USE_ZLIB=on . && sudo make install -j`
1. [Microsoft Kuku 1.1.1](https://github.com/microsoft/Kuku)
    - Linux: `cmake . && sudo make install -j`
1. [Log4cplus](https://github.com/log4cplus/log4cplus)
    - Linux:
        ```
        git clone git@github.com:log4cplus/log4cplus.git --recurse-submodules
        cd log4cplus
        git checkout 2.0.x
        ./configure
        cmake .
        sudo make install -j
        ```
1. [ZeroMQ](http://zeromq.org)
    1. [libzmq](https://github.com/zeromq/libzmq) - ZeroMQ base
        - Linux: will be installed as a dependency of libzmqpp
    1. [libzmqpp](https://github.com/zeromq/zmqpp) - ZeroMQ C++ wrapper
        - Linux: `sudo apt install libzmqpp-dev`
1. [FourQlib](https://github.com/kiromaru/FourQlib)
    - Linux: add "SHARED_LIB=TRUE" to makefile
        ```
        git clone git@github.com:kiromaru/FourQlib.git
        cd FourQlib/FourQ_64bit_and_portable
        make -j
        sudo cp *.h /usr/local/include
        sudo cp libFourQ.so /usr/local/lib
        ```

## Questions
TODO: All CMakeFiles need to know whether we are building shared or static?

### Additional requirements
- [Google Test](https://github.com/google/googletest) - For unit tests and integration tests projects
- [TCLAP](https://sourceforge.net/projects/tclap/) - Command line parser for stand alone executables (Receiver / Sender)
    - Linux: `sudo apt install libtclap-dev `
