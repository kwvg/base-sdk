//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// The bls::Threshold subset Dash Core calls: PrivateKeyShare,
// PublicKeyShare and SignatureRecover.

#ifndef DASHPKC_THRESHOLD_H
#define DASHPKC_THRESHOLD_H

#include <cstdint>
#include <span>
#include <vector>

#include "dashpkc/elements.h"
#include "dashpkc/expected.h"
#include "dashpkc/privatekey.h"

namespace dash_pkc::Threshold {

// Evaluate the secret polynomial `sks` at the 32-byte participant
// `id` (dashbls Threshold::PrivateKeyShare).
Expected<PrivateKey>
PrivateKeyShare(const std::vector<PrivateKey>& sks, std::span<const uint8_t> id);

// Evaluate the public polynomial `pks` at the 32-byte participant
// `id` (dashbls Threshold::PublicKeyShare).
Expected<G1Element> PublicKeyShare(const std::vector<G1Element>& pks, std::span<const uint8_t> id);

// Recover a threshold signature from shares and their 32-byte ids
// via Lagrange interpolation (dashbls Threshold::SignatureRecover).
Expected<G2Element>
SignatureRecover(const std::vector<G2Element>& sigs, const std::vector<std::vector<uint8_t>>& ids);

} // namespace dash_pkc::Threshold

#endif // DASHPKC_THRESHOLD_H
