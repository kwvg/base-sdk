//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Version bits deployment parameters.

use dash_params::{Bip9Deployment, Network};
use rstest::rstest;

#[rstest]
#[case::mainnet(Network::Main)]
#[case::testnet(Network::Testnet3)]
#[case::regtest(Network::Regtest)]
fn v24_signals_on_bit_13(#[case] network: Network) {
  // Bit 12 carries MNHF signals mined before v24 had a start time.
  assert_eq!(network.consensus().deployments.v24.bit, 13);
}

#[rstest]
#[case::mainnet(Network::Main, Bip9Deployment::NEVER_ACTIVE)]
#[case::testnet(Network::Testnet3, 1_790_208_000)]
#[case::regtest(Network::Regtest, 0)]
fn v24_start_time(#[case] network: Network, #[case] expected: i64) {
  assert_eq!(network.consensus().deployments.v24.start_time, expected);
}
