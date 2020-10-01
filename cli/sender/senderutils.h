// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <memory>

// APSI
#include "sender/clp.h"
#include "apsi/psiparams.h"

std::unique_ptr<apsi::PSIParams> build_psi_params(const CLP &cmd);
