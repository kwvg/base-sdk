//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#include "dashpkc/privatekey.h"

#include "detail.h"

namespace dash_pkc {

PrivateKey::PrivateKey() noexcept = default;
PrivateKey::PrivateKey(PrivateKey&&) noexcept = default;
PrivateKey& PrivateKey::operator=(PrivateKey&&) noexcept = default;
PrivateKey::~PrivateKey() = default;

PrivateKey::PrivateKey(const PrivateKey& other)
    : impl_(other.impl_ ? other.impl_->clone() : nullptr)
{
}

PrivateKey& PrivateKey::operator=(const PrivateKey& other)
{
  if (this != &other) {
    impl_ = other.impl_ ? other.impl_->clone() : nullptr;
  }
  return *this;
}

PrivateKey::PrivateKey(std::unique_ptr<ffi::SecretKey> impl) noexcept
    : impl_(std::move(impl))
{
}

bool PrivateKey::IsNull() const noexcept
{
  return impl_ == nullptr;
}

const ffi::SecretKey& PrivateKey::Impl() const
{
  return *impl_;
}

Expected<PrivateKey> PrivateKey::FromBytes(std::span<const uint8_t> bytes, bool modOrder)
{
  // modOrder is accepted for dashbls signature compatibility but
  // ignored: out-of-range scalars are always rejected rather than
  // reduced.
  (void)modOrder;
  return detail::WrapPtr<PrivateKey>(ffi::SecretKey::from_bytes(bytes));
}

Expected<PrivateKey> PrivateKey::FromByteVector(const std::vector<uint8_t>& bytes, bool modOrder)
{
  return FromBytes(std::span<const uint8_t>(bytes.data(), bytes.size()), modOrder);
}

Expected<PrivateKey> PrivateKey::KeyGen(std::span<const uint8_t> seed)
{
  return detail::WrapPtr<PrivateKey>(ffi::SecretKey::generate(seed));
}

Expected<PrivateKey> PrivateKey::Aggregate(const std::vector<PrivateKey>& keys)
{
  const auto vec = detail::MakeVec(keys);
  if (!vec) {
    return tl::unexpected(Error::InvalidSecretKey);
  }
  return detail::WrapPtr<PrivateKey>(ffi::SecretKey::aggregate(*vec));
}

Expected<G1Element> PrivateKey::GetG1Element(bool fLegacy) const
{
  if (!impl_) {
    return tl::unexpected(Error::InvalidSecretKey);
  }
  return detail::WrapPtr<G1Element>(impl_->public_key(detail::ToScheme(fLegacy)));
}

Expected<G2Element> PrivateKey::Sign(std::span<const uint8_t> msg, bool fLegacy) const
{
  if (!impl_) {
    return tl::unexpected(Error::InvalidSecretKey);
  }
  return detail::WrapPtr<G2Element>(impl_->sign(msg, detail::ToScheme(fLegacy)));
}

std::array<uint8_t, PrivateKey::PRIVATE_KEY_SIZE> PrivateKey::SerializeToArray() const
{
  std::array<uint8_t, PRIVATE_KEY_SIZE> out{};
  if (impl_) {
    (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()));
  }
  return out;
}

std::array<uint8_t, PrivateKey::PRIVATE_KEY_SIZE> PrivateKey::SerializeToArray(bool fLegacy) const
{
  (void)fLegacy; // secret scalars are scheme invariant, as in dashbls
  return SerializeToArray();
}

std::vector<uint8_t> PrivateKey::Serialize(bool fLegacy) const
{
  (void)fLegacy;
  const auto arr = SerializeToArray();
  return {arr.begin(), arr.end()};
}

bool operator==(const PrivateKey& a, const PrivateKey& b)
{
  if (!a.impl_ || !b.impl_) {
    return a.impl_ == b.impl_;
  }
  return a.impl_->eq(*b.impl_);
}

bool operator!=(const PrivateKey& a, const PrivateKey& b)
{
  return !(a == b);
}

Expected<G1Element> DHKeyExchange(const PrivateKey& sk, const G1Element& pk)
{
  if (sk.IsNull() || pk.IsNull()) {
    return tl::unexpected(Error::InvalidPublicKey);
  }
  return detail::WrapPtr<G1Element>(sk.Impl().dh_exchange(pk.Impl()));
}

} // namespace dash_pkc
