//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Address encoding parameters.

use dash_params::Network;
use rstest::rstest;

#[rstest]
#[case::mainnet(Network::Main, "dash")]
#[case::testnet(Network::Testnet3, "tdash")]
#[case::regtest(Network::Regtest, "tdash")]
fn platform_hrp(#[case] network: Network, #[case] expected: &str) {
  assert_eq!(network.addr().platform_hrp, expected);
}
