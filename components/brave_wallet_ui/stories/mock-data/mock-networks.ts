// Copyright (c) 2021 The Brave Authors. All rights reserved.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// you can obtain one at https://mozilla.org/MPL/2.0/.

import { BraveWallet } from '../../constants/types'
import {
  ETHIcon,
  FILECOINIcon,
  SOLIcon,
  BTCIcon,
  BNBIcon,
} from '../../assets/network_token_icons/network_token_icons'

export const mockEthMainnet: BraveWallet.NetworkInfo = {
  activeRpcEndpointIndex: 0,
  blockExplorerUrls: ['https://etherscan.io', 'https://etherchain.org'],
  chainId: BraveWallet.MAINNET_CHAIN_ID,
  chainName: 'Ethereum Mainnet',
  coin: BraveWallet.CoinType.ETH,
  supportedKeyrings: [BraveWallet.KeyringId.kDefault],
  decimals: 18,
  iconUrls: [ETHIcon],
  rpcEndpoints: [{ url: 'https://mainnet.infura.io/v3/' }],
  symbol: 'ETH',
  symbolName: 'Ethereum',
}

export const mockSepolia: BraveWallet.NetworkInfo = {
  activeRpcEndpointIndex: 0,
  blockExplorerUrls: ['https://sepolia.etherscan.io'],
  chainId: BraveWallet.SEPOLIA_CHAIN_ID,
  chainName: 'Sepolia Test Network',
  coin: 60,
  supportedKeyrings: [BraveWallet.KeyringId.kDefault],
  decimals: 18,
  iconUrls: [ETHIcon],
  rpcEndpoints: [{ url: 'https://sepolia-infura.brave.com' }],
  symbol: 'ETH',
  symbolName: 'Ethereum',
}

export const mockEthLocalhost: BraveWallet.NetworkInfo = {
  activeRpcEndpointIndex: 0,
  blockExplorerUrls: ['http://localhost:7545/'],
  chainId: BraveWallet.LOCALHOST_CHAIN_ID,
  chainName: 'Localhost',
  coin: 60,
  supportedKeyrings: [BraveWallet.KeyringId.kDefault],
  decimals: 18,
  iconUrls: [ETHIcon],
  rpcEndpoints: [{ url: 'http://localhost:7545/' }],
  symbol: 'ETH',
  symbolName: 'Ethereum',
}

export const mockFilecoinMainnetNetwork: BraveWallet.NetworkInfo = {
  chainId: 'f',
  chainName: 'Filecoin Mainnet',
  activeRpcEndpointIndex: 0,
  rpcEndpoints: [{ url: 'https://calibration.node.glif.io/rpc/v0' }],
  blockExplorerUrls: ['https://filscan.io/tipset/message-detail'],
  symbol: 'FIL',
  symbolName: 'Filecoin',
  decimals: 18,
  iconUrls: [FILECOINIcon],
  coin: BraveWallet.CoinType.FIL,
  supportedKeyrings: [BraveWallet.KeyringId.kFilecoin],
}

export const mockFilecoinTestnetNetwork: BraveWallet.NetworkInfo = {
  chainId: 't',
  chainName: 'Filecoin Testnet',
  activeRpcEndpointIndex: 0,
  rpcEndpoints: [{ url: 'https://solana-mainnet.wallet.brave.com' }],
  blockExplorerUrls: ['https://calibration.filscan.io/tipset/message-detail'],
  symbol: 'FIL',
  symbolName: 'Filecoin',
  decimals: 18,
  iconUrls: [FILECOINIcon],
  coin: BraveWallet.CoinType.FIL,
  supportedKeyrings: [BraveWallet.KeyringId.kFilecoinTestnet],
}

export const mockSolanaMainnetNetwork: BraveWallet.NetworkInfo = {
  activeRpcEndpointIndex: 0,
  blockExplorerUrls: ['https://explorer.solana.com'],
  chainId: '0x65',
  chainName: 'Solana Mainnet Beta',
  coin: BraveWallet.CoinType.SOL,
  supportedKeyrings: [BraveWallet.KeyringId.kSolana],
  decimals: 9,
  iconUrls: [SOLIcon],
  rpcEndpoints: [{ url: 'https://api.testnet.solana.com' }],
  symbol: 'SOL',
  symbolName: 'Solana',
}

export const mockSolanaTestnetNetwork: BraveWallet.NetworkInfo = {
  chainId: '0x66',
  chainName: 'Solana Testnet',
  activeRpcEndpointIndex: 0,
  rpcEndpoints: [{ url: 'https://api.testnet.solana.com' }],
  blockExplorerUrls: ['https://explorer.solana.com?cluster=testnet'],
  symbol: 'SOL',
  symbolName: 'Solana',
  decimals: 9,
  iconUrls: [SOLIcon],
  coin: BraveWallet.CoinType.SOL,
  supportedKeyrings: [BraveWallet.KeyringId.kSolana],
}

export const mockBitcoinMainnet: BraveWallet.NetworkInfo = {
  activeRpcEndpointIndex: 0,
  blockExplorerUrls: ['https://bitcoin.explorer'],
  chainId: 'bitcoin_mainnet',
  chainName: 'Bitcoin Mainnet',
  coin: BraveWallet.CoinType.BTC,
  supportedKeyrings: [BraveWallet.KeyringId.kBitcoin84],
  decimals: 8,
  iconUrls: [BTCIcon],
  rpcEndpoints: [{ url: 'https://bitcoin.rpc' }],
  symbol: 'BTC',
  symbolName: 'Bitcoin',
}

export const mockBitcoinTestnet: BraveWallet.NetworkInfo = {
  activeRpcEndpointIndex: 0,
  blockExplorerUrls: ['https://bitcoin.explorer'],
  chainId: 'bitcoin_testnet',
  chainName: 'Bitcoin Testnet',
  coin: BraveWallet.CoinType.BTC,
  supportedKeyrings: [BraveWallet.KeyringId.kBitcoin84Testnet],
  decimals: 8,
  iconUrls: [BTCIcon],
  rpcEndpoints: [{ url: 'https://bitcoin.rpc/test' }],
  symbol: 'BTC',
  symbolName: 'Bitcoin',
}

export const mockBNBChainNetwork: BraveWallet.NetworkInfo = {
  chainId: '0x38',
  chainName: 'BNB Smart Chain Mainnet',
  activeRpcEndpointIndex: 0,
  rpcEndpoints: [{ url: 'https://bsc-mainnet.wallet.brave.com/' }],
  blockExplorerUrls: ['https://bscscan.com'],
  symbol: 'BNB',
  symbolName: 'BNB',
  decimals: 18,
  iconUrls: [BNBIcon],
  coin: BraveWallet.CoinType.ETH,
  supportedKeyrings: [BraveWallet.KeyringId.kDefault],
}

export const mockNetworks: BraveWallet.NetworkInfo[] = [
  mockEthMainnet,
  mockSepolia,
  mockFilecoinMainnetNetwork,
  mockFilecoinTestnetNetwork,
  mockSolanaMainnetNetwork,
  mockSolanaTestnetNetwork,
  mockEthLocalhost,
  mockBitcoinMainnet,
  mockBNBChainNetwork,
]
