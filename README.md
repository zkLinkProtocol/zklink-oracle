## Overview

This is a plonkish circuit implementation of verification of a batch of price feeds from pyth network. The backend proof system is `better_better_cs` (a plonk implmentation by zk-sync).

### Usage

The entry circuit is `ZkLinkOracle`. It accepts a [`AccumulatorUpdateData`](https://github.com/pyth-network/pyth-crosschain/blob/6463f1a98fcaa63e3d60b128b46ff08181ce8c1f/pythnet/pythnet_sdk/src/wire.rs#L60-L66) that can be got by deserializing base64-encoded response from Hermes' [`/api/latest_vaas`](https://hermes.pyth.network/docs/#/rest/latest_vaas).

## LICENSE

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

zklink-oracle is built on [era-sync_vm](https://github.com/matter-labs/era-sync_vm) implemented by zksync. Thanks for all they’ve done for the zk community.

## Disclaimer

zklink-oracle has not undergone any formal audit. We (zkLink) cannot assure the security or reliability of the project. Any potential issues should be considered the user's responsibility.
