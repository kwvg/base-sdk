//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#include "dashpkc/elements.h"

#include "dashpkc/privatekey.h"
#include "detail.h"

namespace dash_pkc {

namespace detail {

std::unique_ptr<ffi::PublicKeyVec> MakeVec(const std::vector<G1Element>& pks)
{
  auto vec = ffi::PublicKeyVec::new_();
  for (const auto& pk : pks) {
    if (pk.IsNull()) {
      return nullptr;
    }
    vec->push(pk.Impl());
  }
  return vec;
}

std::unique_ptr<ffi::SignatureVec> MakeVec(const std::vector<G2Element>& sigs)
{
  auto vec = ffi::SignatureVec::new_();
  for (const auto& sig : sigs) {
    if (sig.IsNull()) {
      return nullptr;
    }
    vec->push(sig.Impl());
  }
  return vec;
}

std::unique_ptr<ffi::MessageVec> MakeVec(const std::vector<std::vector<uint8_t>>& msgs)
{
  auto vec = ffi::MessageVec::new_();
  for (const auto& msg : msgs) {
    vec->push(std::span<const uint8_t>(msg.data(), msg.size()));
  }
  return vec;
}

std::unique_ptr<ffi::SecretKeyVec> MakeVec(const std::vector<PrivateKey>& sks)
{
  auto vec = ffi::SecretKeyVec::new_();
  for (const auto& sk : sks) {
    if (sk.IsNull()) {
      return nullptr;
    }
    vec->push(sk.Impl());
  }
  return vec;
}

} // namespace detail

G1Element::G1Element() noexcept = default;
G1Element::G1Element(G1Element&&) noexcept = default;
G1Element& G1Element::operator=(G1Element&&) noexcept = default;
G1Element::~G1Element() = default;

G1Element::G1Element(const G1Element& other)
    : impl_(other.impl_ ? other.impl_->clone() : nullptr)
{
}

G1Element& G1Element::operator=(const G1Element& other)
{
  if (this != &other) {
    impl_ = other.impl_ ? other.impl_->clone() : nullptr;
  }
  return *this;
}

G1Element::G1Element(std::unique_ptr<ffi::PublicKey> impl) noexcept
    : impl_(std::move(impl))
{
}

bool G1Element::IsNull() const noexcept
{
  return impl_ == nullptr;
}

const ffi::PublicKey& G1Element::Impl() const
{
  return *impl_;
}

Expected<G1Element> G1Element::FromBytes(std::span<const uint8_t> bytes, bool fLegacy)
{
  return detail::WrapPtr<G1Element>(ffi::PublicKey::from_bytes(bytes, detail::ToScheme(fLegacy)));
}

Expected<G1Element> G1Element::FromByteVector(const std::vector<uint8_t>& bytes, bool fLegacy)
{
  return FromBytes(std::span<const uint8_t>(bytes.data(), bytes.size()), fLegacy);
}

std::array<uint8_t, G1Element::SIZE> G1Element::SerializeToArray(bool fLegacy) const
{
  std::array<uint8_t, SIZE> out{};
  if (impl_) {
    (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()), detail::ToScheme(fLegacy));
  }
  return out;
}

std::vector<uint8_t> G1Element::Serialize(bool fLegacy) const
{
  const auto arr = SerializeToArray(fLegacy);
  return {arr.begin(), arr.end()};
}

bool G1Element::IsLegacy() const
{
  return impl_ && impl_->scheme() == ffi::Scheme::Legacy;
}

bool operator==(const G1Element& a, const G1Element& b)
{
  if (!a.impl_ || !b.impl_) {
    return a.impl_ == b.impl_;
  }
  return a.impl_->eq(*b.impl_);
}

bool operator!=(const G1Element& a, const G1Element& b)
{
  return !(a == b);
}

G2Element::G2Element() noexcept = default;
G2Element::G2Element(G2Element&&) noexcept = default;
G2Element& G2Element::operator=(G2Element&&) noexcept = default;
G2Element::~G2Element() = default;

G2Element::G2Element(const G2Element& other)
    : impl_(other.impl_ ? other.impl_->clone() : nullptr)
{
}

G2Element& G2Element::operator=(const G2Element& other)
{
  if (this != &other) {
    impl_ = other.impl_ ? other.impl_->clone() : nullptr;
  }
  return *this;
}

G2Element::G2Element(std::unique_ptr<ffi::Signature> impl) noexcept
    : impl_(std::move(impl))
{
}

bool G2Element::IsNull() const noexcept
{
  return impl_ == nullptr;
}

const ffi::Signature& G2Element::Impl() const
{
  return *impl_;
}

Expected<G2Element> G2Element::FromBytes(std::span<const uint8_t> bytes, bool fLegacy)
{
  return detail::WrapPtr<G2Element>(ffi::Signature::from_bytes(bytes, detail::ToScheme(fLegacy)));
}

Expected<G2Element> G2Element::FromByteVector(const std::vector<uint8_t>& bytes, bool fLegacy)
{
  return FromBytes(std::span<const uint8_t>(bytes.data(), bytes.size()), fLegacy);
}

std::array<uint8_t, G2Element::SIZE> G2Element::SerializeToArray(bool fLegacy) const
{
  std::array<uint8_t, SIZE> out{};
  if (impl_) {
    (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()), detail::ToScheme(fLegacy));
  }
  return out;
}

std::vector<uint8_t> G2Element::Serialize(bool fLegacy) const
{
  const auto arr = SerializeToArray(fLegacy);
  return {arr.begin(), arr.end()};
}

bool G2Element::IsLegacy() const
{
  return impl_ && impl_->scheme() == ffi::Scheme::Legacy;
}

Expected<G2Element> G2Element::SubInsecure(const G2Element& other) const
{
  if (!impl_ || !other.impl_) {
    return tl::unexpected(Error::InvalidSignature);
  }
  return detail::WrapPtr<G2Element>(impl_->sub_insecure(*other.impl_));
}

bool operator==(const G2Element& a, const G2Element& b)
{
  if (!a.impl_ || !b.impl_) {
    return a.impl_ == b.impl_;
  }
  return a.impl_->eq(*b.impl_);
}

bool operator!=(const G2Element& a, const G2Element& b)
{
  return !(a == b);
}

} // namespace dash_pkc
