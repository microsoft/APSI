// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.using System;

// STD
#include <stdexcept>
#include <memory>

// APSI
#include "apsi/ffield/ffield.h"
#include "apsi/ffield/ffield_elt.h"

using namespace seal;
using namespace std;

namespace apsi
{
    FFieldElt FField::zero()
    {
        return FFieldElt(*this);
    }

    FFieldElt FField::one()
    {
        FFieldElt one(*this);
        one.set_one();
        return one;
    }
}
