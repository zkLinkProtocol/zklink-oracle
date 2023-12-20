## Overview

This is a plonkish circuit implementation of verification of a batch of price feeds from pyth network. The backend proof system is `better_better_cs` (a plonk implmentation by zk-sync).

### Usage

Check out [the example](examples/verify_price.rs) to learn how to use. You can get a new base64-encoded VAA from Hermes' [`/api/latest_vaas`](https://hermes.pyth.network/docs/#/rest/latest_vaas).

## LICENSE

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

zklink-oracle is built on [era-sync_vm](https://github.com/matter-labs/era-sync_vm) implemented by zksync. Thanks for all they’ve done for the zk community.

## Disclaimer

zklink-oracle has not undergone any formal audit. We (zkLink) cannot assure the security or reliability of the project. Any potential issues should be considered the user's responsibility.
