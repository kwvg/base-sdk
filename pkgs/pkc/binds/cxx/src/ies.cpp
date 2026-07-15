//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#include "dashpkc/ies.h"

#include "detail.h"

namespace dash_pkc {

IESBlob::IESBlob(IESBlob&&) noexcept = default;
IESBlob& IESBlob::operator=(IESBlob&&) noexcept = default;
IESBlob::~IESBlob() = default;

IESBlob::IESBlob(std::unique_ptr<ffi::IesBlob> impl) noexcept
    : impl_(std::move(impl))
{
}

const ffi::IesBlob& IESBlob::Impl() const
{
  return *impl_;
}

Expected<IESBlob> IESBlob::Encrypt(
    const G1Element& recipient, std::span<const uint8_t> plaintext, std::span<const uint8_t> entropy
)
{
  if (recipient.IsNull()) {
    return tl::unexpected(Error::InvalidPublicKey);
  }
  return detail::WrapPtr<IESBlob>(recipient.Impl().ies_encrypt(plaintext, entropy));
}

Expected<std::vector<uint8_t>>
IESBlob::Decrypt(const PrivateKey& sk, size_t index, bool fLegacy) const
{
  if (sk.IsNull()) {
    return tl::unexpected(Error::InvalidSecretKey);
  }
  std::vector<uint8_t> plain(impl_->data_len());
  auto res = sk.Impl().ies_decrypt(
      *impl_, index, detail::ToScheme(fLegacy), std::span<uint8_t>(plain.data(), plain.size())
  );
  if (!res.is_ok()) {
    return tl::unexpected(detail::FromFfi(*std::move(res).err()));
  }
  return plain;
}

Expected<IESBlob> IESBlob::FromBytes(std::span<const uint8_t> bytes)
{
  return detail::WrapPtr<IESBlob>(ffi::IesBlob::from_bytes(bytes));
}

std::vector<uint8_t> IESBlob::Serialize() const
{
  std::vector<uint8_t> out(impl_->encoded_len());
  (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()));
  return out;
}

size_t IESBlob::DataSize() const
{
  return impl_->data_len();
}

IESMultiBlob::IESMultiBlob(IESMultiBlob&&) noexcept = default;
IESMultiBlob& IESMultiBlob::operator=(IESMultiBlob&&) noexcept = default;
IESMultiBlob::~IESMultiBlob() = default;

IESMultiBlob::IESMultiBlob(std::unique_ptr<ffi::IesMultiBlob> impl) noexcept
    : impl_(std::move(impl))
{
}

const ffi::IesMultiBlob& IESMultiBlob::Impl() const
{
  return *impl_;
}

Expected<IESMultiBlob> IESMultiBlob::Encrypt(
    const std::vector<G1Element>& recipients,
    const std::vector<std::vector<uint8_t>>& plaintexts,
    std::span<const uint8_t> entropy
)
{
  const auto vec = detail::MakeVec(recipients);
  if (!vec) {
    return tl::unexpected(Error::InvalidPublicKey);
  }
  const ffi::Scheme scheme =
      recipients.empty() ? ffi::Scheme(ffi::Scheme::Basic) : recipients.front().Impl().scheme();
  return detail::WrapPtr<IESMultiBlob>(
      ffi::PublicKey::ies_encrypt_multi(*vec, *detail::MakeVec(plaintexts), entropy, scheme)
  );
}

Expected<std::vector<uint8_t>>
IESMultiBlob::Decrypt(size_t index, const PrivateKey& sk, bool fLegacy) const
{
  auto len = impl_->data_len_at(index);
  if (!len.is_ok()) {
    return tl::unexpected(detail::FromFfi(*std::move(len).err()));
  }
  if (sk.IsNull()) {
    return tl::unexpected(Error::InvalidSecretKey);
  }
  std::vector<uint8_t> plain(*std::move(len).ok());
  auto res = sk.Impl().ies_decrypt_multi(
      *impl_, index, detail::ToScheme(fLegacy), std::span<uint8_t>(plain.data(), plain.size())
  );
  if (!res.is_ok()) {
    return tl::unexpected(detail::FromFfi(*std::move(res).err()));
  }
  return plain;
}

Expected<IESMultiBlob> IESMultiBlob::FromBytes(std::span<const uint8_t> bytes)
{
  return detail::WrapPtr<IESMultiBlob>(ffi::IesMultiBlob::from_bytes(bytes));
}

std::vector<uint8_t> IESMultiBlob::Serialize() const
{
  std::vector<uint8_t> out(impl_->encoded_len());
  (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()));
  return out;
}

size_t IESMultiBlob::BlobCount() const
{
  return impl_->blob_count();
}

} // namespace dash_pkc
