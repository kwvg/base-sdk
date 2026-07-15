//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#include "dashpkc/schemes.h"

#include "detail.h"

namespace dash_pkc {

Expected<PrivateKey> CoreMPL::KeyGen(std::span<const uint8_t> seed) const
{
  return PrivateKey::KeyGen(seed);
}

Expected<G2Element> CoreMPL::Sign(const PrivateKey& sk, std::span<const uint8_t> msg) const
{
  return sk.Sign(msg, fLegacy_);
}

bool CoreMPL::Verify(const G1Element& pk, std::span<const uint8_t> msg, const G2Element& sig) const
{
  if (pk.IsNull() || sig.IsNull()) {
    return false;
  }
  return sig.Impl().verify(msg, pk.Impl(), detail::ToScheme(fLegacy_)).is_ok();
}

Expected<G1Element> CoreMPL::Aggregate(const G1Element& a, const G1Element& b) const
{
  if (a.IsNull() || b.IsNull()) {
    return tl::unexpected(Error::InvalidPublicKey);
  }
  return detail::WrapPtr<G1Element>(a.Impl().aggregate_with(b.Impl(), detail::ToScheme(fLegacy_)));
}

Expected<G2Element> CoreMPL::Aggregate(const G2Element& a, const G2Element& b) const
{
  if (a.IsNull() || b.IsNull()) {
    return tl::unexpected(Error::InvalidSignature);
  }
  return detail::WrapPtr<G2Element>(a.Impl().aggregate_with(b.Impl(), detail::ToScheme(fLegacy_)));
}

Expected<G1Element> CoreMPL::Aggregate(const std::vector<G1Element>& pks) const
{
  const auto vec = detail::MakeVec(pks);
  if (!vec) {
    return tl::unexpected(Error::InvalidPublicKey);
  }
  return detail::WrapPtr<G1Element>(ffi::PublicKey::aggregate(*vec, detail::ToScheme(fLegacy_)));
}

Expected<G2Element> CoreMPL::Aggregate(const std::vector<G2Element>& sigs) const
{
  const auto vec = detail::MakeVec(sigs);
  if (!vec) {
    return tl::unexpected(Error::InvalidSignature);
  }
  return detail::WrapPtr<G2Element>(ffi::Signature::aggregate(*vec, detail::ToScheme(fLegacy_)));
}

Expected<G2Element> CoreMPL::AggregateSecure(
    const std::vector<G1Element>& pks,
    const std::vector<G2Element>& sigs,
    std::span<const uint8_t> msg
) const
{
  (void)msg; // weights depend only on the sorted public keys
  const auto sigVec = detail::MakeVec(sigs);
  const auto pkVec = detail::MakeVec(pks);
  if (!sigVec || !pkVec) {
    return tl::unexpected(Error::InvalidSignature);
  }
  return detail::WrapPtr<G2Element>(
      ffi::Signature::aggregate_secure(*sigVec, *pkVec, detail::ToScheme(fLegacy_))
  );
}

bool CoreMPL::VerifySecure(
    const std::vector<G1Element>& pks, const G2Element& sig, std::span<const uint8_t> msg
) const
{
  const auto vec = detail::MakeVec(pks);
  if (!vec || sig.IsNull()) {
    return false;
  }
  return sig.Impl().verify_secure(*vec, msg, detail::ToScheme(fLegacy_)).is_ok();
}

bool CoreMPL::AggregateVerify(
    const std::vector<G1Element>& pks,
    const std::vector<std::vector<uint8_t>>& msgs,
    const G2Element& sig
) const
{
  const auto vec = detail::MakeVec(pks);
  if (!vec || sig.IsNull()) {
    return false;
  }
  return sig.Impl()
      .verify_aggregated(*detail::MakeVec(msgs), *vec, detail::ToScheme(fLegacy_))
      .is_ok();
}

} // namespace dash_pkc
