//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#include "dashpkc/session.h"

#include "detail.h"

namespace dash_pkc {

Session::Session(Session&&) noexcept = default;
Session& Session::operator=(Session&&) noexcept = default;
Session::~Session() = default;

Session::Session(std::unique_ptr<ffi::Session> impl) noexcept
    : impl_(std::move(impl))
{
}

const ffi::Session& Session::Impl() const
{
  return *impl_;
}

Expected<Session> Session::Create(std::span<const uint8_t> entropy)
{
  return detail::WrapPtr<Session>(ffi::Session::create(entropy));
}

bool Session::Verify(
    const G1Element& pk, std::span<const uint8_t> msg, const G2Element& sig, bool fLegacy
) const
{
  if (pk.IsNull() || sig.IsNull()) {
    return false;
  }
  return impl_->verify(sig.Impl(), msg, pk.Impl(), detail::ToScheme(fLegacy)).is_ok();
}

bool Session::VerifyAggregated(
    const std::vector<G1Element>& pks,
    const std::vector<std::vector<uint8_t>>& msgs,
    const G2Element& sig,
    bool fLegacy
) const
{
  const auto vec = detail::MakeVec(pks);
  if (!vec || sig.IsNull()) {
    return false;
  }
  return impl_
      ->verify_aggregated(sig.Impl(), *detail::MakeVec(msgs), *vec, detail::ToScheme(fLegacy))
      .is_ok();
}

bool Session::VerifySecure(
    const std::vector<G1Element>& pks,
    const G2Element& sig,
    std::span<const uint8_t> msg,
    bool fLegacy
) const
{
  const auto vec = detail::MakeVec(pks);
  if (!vec || sig.IsNull()) {
    return false;
  }
  return impl_->verify_secure(sig.Impl(), *vec, msg, detail::ToScheme(fLegacy)).is_ok();
}

Expected<G2Element> Session::AggregateSecure(
    const std::vector<G1Element>& pks, const std::vector<G2Element>& sigs, bool fLegacy
) const
{
  const auto sigVec = detail::MakeVec(sigs);
  const auto pkVec = detail::MakeVec(pks);
  if (!sigVec || !pkVec) {
    return tl::unexpected(Error::InvalidSignature);
  }
  return detail::WrapPtr<G2Element>(
      impl_->aggregate_secure(*sigVec, *pkVec, detail::ToScheme(fLegacy))
  );
}

Expected<G1Element> Session::ParsePublicKey(std::span<const uint8_t> bytes, bool fLegacy) const
{
  return detail::WrapPtr<G1Element>(impl_->parse_public_key(bytes, detail::ToScheme(fLegacy)));
}

Expected<G2Element> Session::ParseSignature(std::span<const uint8_t> bytes, bool fLegacy) const
{
  return detail::WrapPtr<G2Element>(impl_->parse_signature(bytes, detail::ToScheme(fLegacy)));
}

Expected<G1Element>
Session::PublicKeyShare(const std::vector<G1Element>& pks, std::span<const uint8_t> id) const
{
  const auto vec = detail::MakeVec(pks);
  if (!vec) {
    return tl::unexpected(Error::InvalidPublicKey);
  }
  const ffi::Scheme scheme =
      pks.empty() ? ffi::Scheme(ffi::Scheme::Basic) : pks.front().Impl().scheme();
  return detail::WrapPtr<G1Element>(impl_->public_key_share(*vec, id, scheme));
}

Expected<G2Element> Session::SignatureRecover(
    const std::vector<G2Element>& sigs, const std::vector<std::vector<uint8_t>>& ids
) const
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
  return detail::WrapPtr<G2Element>(impl_->recover_signature(*vec, *idVec, scheme));
}

} // namespace dash_pkc
