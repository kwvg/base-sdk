//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// BLS-IES encrypted blobs in Dash Core's on-wire format
// (CBLSIESEncryptedBlob / CBLSIESMultiRecipientBlobs equivalents).

#ifndef DASH_PKC_IES_HPP
#define DASH_PKC_IES_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dash_pkc/elements.hpp"
#include "dash_pkc/error.hpp"
#include "dash_pkc/ffi/IesBlob.hpp"
#include "dash_pkc/ffi/IesMultiBlob.hpp"
#include "dash_pkc/privatekey.hpp"
#include "dash_pkc/schemes.hpp"

namespace dash_pkc {

// Entropy each Encrypt call consumes: 32 bytes of ephemeral key
// seed plus 32 bytes of IV seed. The caller sources randomness
// (e.g. GetStrongRandBytes); the library never does.
inline constexpr size_t IES_ENTROPY_SIZE = 64;

// Single-recipient encrypted blob. Plaintext length must be a
// multiple of the AES block size (16); AES-256-CBC is unpadded, so
// ciphertext and plaintext lengths coincide.
class IESBlob {
public:
    static Expected<IESBlob> Encrypt(const G1Element& recipient,
                                     std::span<const uint8_t> plaintext,
                                     std::span<const uint8_t> entropy)
    {
        if (recipient.IsNull()) {
            return tl::unexpected(Error::InvalidPublicKey);
        }
        return detail::WrapPtr<IESBlob>(recipient.Impl().ies_encrypt(plaintext, entropy));
    }

    // `index` selects the IV in the SHA256d chain: 0 for standalone
    // blobs, the original recipient index for blobs extracted from
    // a multi-recipient container. `fLegacy` must match the scheme
    // the blob was encrypted under.
    Expected<std::vector<uint8_t>> Decrypt(const PrivateKey& sk, size_t index = 0, bool fLegacy = false) const
    {
        if (sk.IsNull()) {
            return tl::unexpected(Error::InvalidSecretKey);
        }
        std::vector<uint8_t> plain(impl_->data_len());
        auto res = sk.Impl().ies_decrypt(*impl_, index, detail::ToScheme(fLegacy),
                                         std::span<uint8_t>(plain.data(), plain.size()));
        if (!res.is_ok()) {
            return tl::unexpected(FromFfi(*std::move(res).err()));
        }
        return plain;
    }

    static Expected<IESBlob> FromBytes(std::span<const uint8_t> bytes)
    {
        return detail::WrapPtr<IESBlob>(ffi::IesBlob::from_bytes(bytes));
    }

    std::vector<uint8_t> Serialize() const
    {
        std::vector<uint8_t> out(impl_->encoded_len());
        (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()));
        return out;
    }

    size_t DataSize() const { return impl_->data_len(); }

    // Internal: wrap an FFI handle (must be non-null).
    explicit IESBlob(std::unique_ptr<ffi::IesBlob> impl) noexcept : impl_(std::move(impl)) {}
    const ffi::IesBlob& Impl() const { return *impl_; }

private:
    std::unique_ptr<ffi::IesBlob> impl_;
};

// Multi-recipient encrypted blob: one plaintext per recipient under
// a shared ephemeral key, IVs chained per recipient index.
class IESMultiBlob {
public:
    static Expected<IESMultiBlob> Encrypt(const std::vector<G1Element>& recipients,
                                          const std::vector<std::vector<uint8_t>>& plaintexts,
                                          std::span<const uint8_t> entropy)
    {
        const auto vec = detail::MakeVec(recipients);
        if (!vec) {
            return tl::unexpected(Error::InvalidPublicKey);
        }
        const ffi::Scheme scheme = recipients.empty() ? ffi::Scheme(ffi::Scheme::Basic) : recipients.front().Impl().scheme();
        return detail::WrapPtr<IESMultiBlob>(
            ffi::PublicKey::ies_encrypt_multi(*vec, *detail::MakeVec(plaintexts), entropy, scheme));
    }

    Expected<std::vector<uint8_t>> Decrypt(size_t index, const PrivateKey& sk, bool fLegacy = false) const
    {
        auto len = impl_->data_len_at(index);
        if (!len.is_ok()) {
            return tl::unexpected(FromFfi(*std::move(len).err()));
        }
        if (sk.IsNull()) {
            return tl::unexpected(Error::InvalidSecretKey);
        }
        std::vector<uint8_t> plain(*std::move(len).ok());
        auto res = sk.Impl().ies_decrypt_multi(*impl_, index, detail::ToScheme(fLegacy),
                                               std::span<uint8_t>(plain.data(), plain.size()));
        if (!res.is_ok()) {
            return tl::unexpected(FromFfi(*std::move(res).err()));
        }
        return plain;
    }

    static Expected<IESMultiBlob> FromBytes(std::span<const uint8_t> bytes)
    {
        return detail::WrapPtr<IESMultiBlob>(ffi::IesMultiBlob::from_bytes(bytes));
    }

    std::vector<uint8_t> Serialize() const
    {
        std::vector<uint8_t> out(impl_->encoded_len());
        (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()));
        return out;
    }

    size_t BlobCount() const { return impl_->blob_count(); }

    // Internal: wrap an FFI handle (must be non-null).
    explicit IESMultiBlob(std::unique_ptr<ffi::IesMultiBlob> impl) noexcept : impl_(std::move(impl)) {}
    const ffi::IesMultiBlob& Impl() const { return *impl_; }

private:
    std::unique_ptr<ffi::IesMultiBlob> impl_;
};

} // namespace dash_pkc

#endif // DASH_PKC_IES_HPP
