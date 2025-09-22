# PocketBlock Open Source  

**PocketBlock** is an open-source payments platform built on the **Stellar blockchain** using the **Stellar Python SDK**. The project enables seamless, fast, and low-cost transfers of **USDC** and **EURC**, making it possible for anyone to send and receive stablecoin payments globally.  

By leveraging Stellar’s infrastructure and Circle’s anchors for USDC and EURC, PocketBlock bridges international payments with local access, offering a reliable solution for cross-border transactions.  

---

## Features  

PocketBlock is fully powered by the **Stellar Python SDK**, which is responsible for all blockchain interactions:  

- **Account Management**  
  - Create and manage Stellar accounts programmatically.  
  - Generate keypairs securely.  
  - Retrieve balances and account activity from Horizon.  

- **Trustline Management**  
  - Automatically set up trustlines for USDC and EURC.  
  - Validate asset availability before transactions.  

- **Payments & Transfers**  
  - Build, sign, and submit on-chain transactions with Stellar SDK.  
  - Send and receive **USDC/EURC** instantly with minimal fees.  

- **Purchases & Deposits**  
  - Enable users to buy stablecoins on-chain.  
  - Support direct integrations with Circle’s anchors for fiat on-ramps.  

- **Withdrawals**  
  - On-chain stablecoin withdrawals via Stellar.  
  - Combine with local payment rails (e.g., Brazil’s PIX) for fiat access.  

- **Data & Transparency**  
  - Query accounts and transactions directly through Horizon.  
  - Provide users with detailed transaction histories and balance updates.  

---

## Tech Stack  

- **Backend**: Python  
- **Blockchain**: Stellar Network Python SDK  
- **Core Library**: [Stellar Python SDK] 
- **Stablecoins**: USDC, EURC (via Circle anchors)  

---
