//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// BLS-IES walkthrough: derive a recipient key pair, encrypt a
// padded message to it, ship the blob over the wire (serialize +
// reparse) and decrypt it. Entropy is the caller's job; here it is
// deliberately fixed so the output is reproducible.

#include <cstdio>
#include <cstdlib>
#include <vector>

#include <dashpkc/dashpkc.h>

int main()
{
  const std::vector<uint8_t> seed(32, 0x42);
  auto recipientSk = dash_pkc::PrivateKey::KeyGen(seed);
  if (!recipientSk.has_value()) {
    std::fprintf(stderr, "keygen: %s\n", dash_pkc::ErrorName(recipientSk.error()));
    return EXIT_FAILURE;
  }
  auto recipientPk = recipientSk->GetG1Element();
  if (!recipientPk.has_value()) {
    return EXIT_FAILURE;
  }

  // AES-256-CBC is unpadded: plaintext length must be a multiple
  // of 16 bytes.
  const std::vector<uint8_t> plaintext{
      'd', 'a', 's', 'h', '-', 'p', 'k', 'c', ' ', 'i', 'e', 's', ' ', 'd', 'e', 'm'
  };

  // Production callers source this from a CSPRNG (Dash Core:
  // GetStrongRandBytes).
  std::vector<uint8_t> entropy(dash_pkc::IES_ENTROPY_SIZE);
  for (size_t i = 0; i < entropy.size(); ++i) {
    entropy[i] = static_cast<uint8_t>(i * 7 + 1);
  }

  auto blob = dash_pkc::IESBlob::Encrypt(*recipientPk, plaintext, entropy);
  if (!blob.has_value()) {
    std::fprintf(stderr, "encrypt: %s\n", dash_pkc::ErrorName(blob.error()));
    return EXIT_FAILURE;
  }

  const auto wire = blob->Serialize();
  std::printf("wire blob: %zu bytes (%zu ciphertext)\n", wire.size(), blob->DataSize());

  auto received = dash_pkc::IESBlob::FromBytes(wire);
  if (!received.has_value()) {
    return EXIT_FAILURE;
  }
  auto decrypted = received->Decrypt(*recipientSk);
  if (!decrypted.has_value()) {
    std::fprintf(stderr, "decrypt: %s\n", dash_pkc::ErrorName(decrypted.error()));
    return EXIT_FAILURE;
  }

  std::printf("decrypted: %.*s\n", static_cast<int>(decrypted->size()), decrypted->data());
  return *decrypted == plaintext ? EXIT_SUCCESS : EXIT_FAILURE;
}
