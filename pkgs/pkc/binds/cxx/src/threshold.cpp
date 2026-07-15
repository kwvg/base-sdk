//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#include "dashpkc/threshold.h"

#include "detail.h"

namespace dash_pkc::Threshold {

Expected<PrivateKey>
PrivateKeyShare(const std::vector<PrivateKey>& sks, std::span<const uint8_t> id)
{
  const auto vec = detail::MakeVec(sks);
  if (!vec) {
    return tl::unexpected(Error::InvalidSecretKey);
  }
  return detail::WrapPtr<PrivateKey>(ffi::SecretKey::derive_share(*vec, id));
}

Expected<G1Element> PublicKeyShare(const std::vector<G1Element>& pks, std::span<const uint8_t> id)
{
  const auto vec = detail::MakeVec(pks);
  if (!vec) {
    return tl::unexpected(Error::InvalidPublicKey);
  }
  const ffi::Scheme scheme =
      pks.empty() ? ffi::Scheme(ffi::Scheme::Basic) : pks.front().Impl().scheme();
  return detail::WrapPtr<G1Element>(ffi::PublicKey::derive_share(*vec, id, scheme));
}

Expected<G2Element>
SignatureRecover(const std::vector<G2Element>& sigs, const std::vector<std::vector<uint8_t>>& ids)
{
  auto idVec = ffi::IdVec::new_();
  for (const auto& id : ids) {
    auto pushed = idVec->push(std::span<const uint8_t>(id.data(), id.size()));
    if (!pushed.is_ok()) {
      return tl::unexpected(detail::FromFfi(*std::move(pushed).err()));
    }
  }
  const auto vec = detail::MakeVec(sigs);
  if (!vec) {
    return tl::unexpected(Error::InvalidSignature);
  }
  const ffi::Scheme scheme =
      sigs.empty() ? ffi::Scheme(ffi::Scheme::Basic) : sigs.front().Impl().scheme();
  return detail::WrapPtr<G2Element>(ffi::Signature::recover(*vec, *idVec, scheme));
}

} // namespace dash_pkc::Threshold
