//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// BLS-IES encrypted blobs in Dash Core's on-wire format
// (CBLSIESEncryptedBlob / CBLSIESMultiRecipientBlobs equivalents).
// Plaintext lengths must be multiples of the AES block size (16);
// AES-256-CBC is unpadded, so ciphertext and plaintext lengths
// coincide. Entropy is supplied by the caller so the library never
// sources randomness.

#ifndef DASHPKC_IES_H
#define DASHPKC_IES_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dashpkc/elements.h"
#include "dashpkc/expected.h"
#include "dashpkc/privatekey.h"

namespace dash_pkc::ffi {
class IesBlob;
class IesMultiBlob;
} // namespace dash_pkc::ffi

namespace dash_pkc {

// Entropy each Encrypt call consumes: 32 bytes of ephemeral key
// seed plus 32 bytes of IV seed.
inline constexpr size_t IES_ENTROPY_SIZE = 64;

class IESBlob
{
public:
  IESBlob(IESBlob&&) noexcept;
  IESBlob& operator=(IESBlob&&) noexcept;
  IESBlob(const IESBlob&) = delete;
  IESBlob& operator=(const IESBlob&) = delete;
  ~IESBlob();

  static Expected<IESBlob> Encrypt(
      const G1Element& recipient,
      std::span<const uint8_t> plaintext,
      std::span<const uint8_t> entropy
  );

  // `index` selects the IV in the SHA256d chain: 0 for standalone
  // blobs, the original recipient index for blobs extracted from a
  // multi-recipient container. `fLegacy` must match the scheme the
  // blob was encrypted under.
  Expected<std::vector<uint8_t>>
  Decrypt(const PrivateKey& sk, size_t index = 0, bool fLegacy = false) const;

  static Expected<IESBlob> FromBytes(std::span<const uint8_t> bytes);
  std::vector<uint8_t> Serialize() const;
  size_t DataSize() const;

  // Internal: wrap an FFI handle (must be non-null).
  explicit IESBlob(std::unique_ptr<ffi::IesBlob> impl) noexcept;
  const ffi::IesBlob& Impl() const;

private:
  std::unique_ptr<ffi::IesBlob> impl_;
};

class IESMultiBlob
{
public:
  IESMultiBlob(IESMultiBlob&&) noexcept;
  IESMultiBlob& operator=(IESMultiBlob&&) noexcept;
  IESMultiBlob(const IESMultiBlob&) = delete;
  IESMultiBlob& operator=(const IESMultiBlob&) = delete;
  ~IESMultiBlob();

  // One plaintext per recipient under a shared ephemeral key, IVs
  // chained per recipient index.
  static Expected<IESMultiBlob> Encrypt(
      const std::vector<G1Element>& recipients,
      const std::vector<std::vector<uint8_t>>& plaintexts,
      std::span<const uint8_t> entropy
  );

  Expected<std::vector<uint8_t>>
  Decrypt(size_t index, const PrivateKey& sk, bool fLegacy = false) const;

  static Expected<IESMultiBlob> FromBytes(std::span<const uint8_t> bytes);
  std::vector<uint8_t> Serialize() const;
  size_t BlobCount() const;

  // Internal: wrap an FFI handle (must be non-null).
  explicit IESMultiBlob(std::unique_ptr<ffi::IesMultiBlob> impl) noexcept;
  const ffi::IesMultiBlob& Impl() const;

private:
  std::unique_ptr<ffi::IesMultiBlob> impl_;
};

} // namespace dash_pkc

#endif // DASHPKC_IES_H
