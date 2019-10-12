#!/bin/bash

makeparallel=-j

function print_banner {
    echo "************************************************************************"
    echo "$1"
    echo "************************************************************************"
}

function build_with_install {
    mkdir -p .build
    cd .build
    cmake .. -DCMAKE_INSTALL_PREFIX=~/mylibs
    make $makeparallel
    make install
    cd ..
}

function build_without_install {
    mkdir -p .build
    cd .build
    cmake .. -DCMAKE_PREFIX_PATH=~/mylibs
    make $makeparallel
    cd ..
}

print_banner "Script that attempts to build all of APSI."

scriptdir=`dirname "$0"`
cd $scriptdir
scriptdir=`pwd`
apsidir=`dirname "$scriptdir"`

# Cuckoo
print_banner "Building Cuckoo"
cd $apsidir/Cuckoo
build_with_install

# APSICommon
print_banner "Building APSICommon"
cd $apsidir/APSICommon
build_with_install

# APSISender
print_banner "Building APSISender"
cd $apsidir/APSISender
build_with_install

# APSIReceiver
print_banner "Building APSIReceiver"
cd $apsidir/APSIReceiver
build_with_install

print_banner "Building APSINative"
cd $apsidir/APSINative
build_without_install

# Unit tests
print_banner "Building APSITest"
cd $apsidir/APSITests
build_without_install

# Integration tests
print_banner "Building IntegrationTests"
cd $apsidir/IntegrationTests
build_without_install

# CommonCLI
print_banner "Building CommonCLI"
cd $apsidir/CommonCLI/
build_without_install

# Sender
print_banner "Building Sender executable"
cd $apsidir/SenderCLI
build_without_install

# Receiver
print_banner "Building Receiver executable"
cd $apsidir/ReceiverCLI
build_without_install

print_banner "Finished."

