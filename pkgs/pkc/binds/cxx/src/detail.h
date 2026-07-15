//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// Private helpers shared by the dashpkc implementation files. Not
// installed; public headers must not include this.

#ifndef DASHPKC_SRC_DETAIL_H
#define DASHPKC_SRC_DETAIL_H

#include <memory>
#include <utility>
#include <vector>

#include "dashpkc/elements.h"
#include "dashpkc/expected.h"

#include "diplomat/dash_pkc/ffi/IdVec.hpp"
#include "diplomat/dash_pkc/ffi/IesBlob.hpp"
#include "diplomat/dash_pkc/ffi/IesMultiBlob.hpp"
#include "diplomat/dash_pkc/ffi/MessageVec.hpp"
#include "diplomat/dash_pkc/ffi/PkcError.hpp"
#include "diplomat/dash_pkc/ffi/PublicKey.hpp"
#include "diplomat/dash_pkc/ffi/PublicKeyVec.hpp"
#include "diplomat/dash_pkc/ffi/Scheme.hpp"
#include "diplomat/dash_pkc/ffi/SecretKey.hpp"
#include "diplomat/dash_pkc/ffi/SecretKeyVec.hpp"
#include "diplomat/dash_pkc/ffi/Session.hpp"
#include "diplomat/dash_pkc/ffi/Signature.hpp"
#include "diplomat/dash_pkc/ffi/SignatureVec.hpp"

namespace dash_pkc {

class G2Element;
class PrivateKey;

namespace detail {

constexpr Error FromFfi(ffi::PkcError err) noexcept
{
  return static_cast<Error>(static_cast<ffi::PkcError::Value>(err));
}

constexpr ffi::Scheme ToScheme(bool fLegacy) noexcept
{
  return fLegacy ? ffi::Scheme::Legacy : ffi::Scheme::Basic;
}

// Unwrap a diplomat pointer result into a wrapper type constructed
// from the unique_ptr.
template <typename Wrapper, typename FfiT>
inline Expected<Wrapper> WrapPtr(diplomat::result<std::unique_ptr<FfiT>, ffi::PkcError>&& res)
{
  if (res.is_ok()) {
    return Wrapper(std::move(*std::move(res).ok()));
  }
  return tl::unexpected(FromFfi(*std::move(res).err()));
}

// Null elements yield a null vec; callers translate that to an
// error instead of dereferencing a null handle.
std::unique_ptr<ffi::PublicKeyVec> MakeVec(const std::vector<G1Element>& pks);
std::unique_ptr<ffi::SignatureVec> MakeVec(const std::vector<G2Element>& sigs);
std::unique_ptr<ffi::MessageVec> MakeVec(const std::vector<std::vector<uint8_t>>& msgs);
std::unique_ptr<ffi::SecretKeyVec> MakeVec(const std::vector<PrivateKey>& sks);

} // namespace detail

} // namespace dash_pkc

#endif // DASHPKC_SRC_DETAIL_H
