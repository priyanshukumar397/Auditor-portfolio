# Ishwar Kumar

Smart Contract Auditor | Application Security Researcher

[Twitter](https://x.com/Ravenzbb) |
[Github](https://github.com/priyanshukumar397) |
[LinkedIn](https://in.linkedin.com/in/ishwar-kumar-214341284) |
[Hackenproof](https://hackenproof.com/hackers/5hax) |
[Email](mailto:231b145@juetguna.in) 

## Findings

| Protocol Name       | Platform   | Total Bugs Reported | High | Med | Low |
|---------------------|------------|---------------------|------|-----|-----|
| OrderBook           | Codehawks  | 2                   | 1    | 0   | 1   |
| Beatland Festival   | Codehawks  | 4                   | 1    | 1   | 2   |
| **Totals**          |            | **6**               | **2**|**1**|**3**|
---

## Smart Contract Work

### OrderBook Audit — Codehawks First Flight #43

* Dates: July 3–10, 2025
* Scope: 217 nSLOC
* Role: Independent auditor
* Rank: Top 25 globally
* Contest: [https://codehawks.cyfrin.io/c/2025-07-orderbook](https://codehawks.cyfrin.io/c/2025-07-orderbook)
* LeaderBoard: [https://codehawks.cyfrin.io/c/2025-07-orderbook/results?lt=contest&page=3&sc=xp&sj=reward&t=leaderboard](https://codehawks.cyfrin.io/c/2025-07-orderbook/results?lt=contest&page=3&sc=xp&sj=reward&t=leaderboard)
* Full Report: [Reports](https://codehawks.cyfrin.io/c/2025-07-orderbook/results?lt=contest&page=1&sc=xp&sj=reward&t=report)

#### L-01. Expired Orders Not Cancellable by Anyone (Design Flaw)

**Root + Impact**

Normally, once an order has expired (past its deadline), it should be possible to remove the order and return tokens to the seller, freeing up storage and preventing locked funds. In the current implementation, only the original seller can cancel their expired order. If the seller becomes inactive or loses access, the expired order cannot be cancelled by anyone else, resulting in tokens being locked in the contract and permanent storage bloat.

```solidity
function cancelSellOrder(uint256 _orderId) public {
    Order storage order = orders[_orderId];

    if (order.seller == address(0)) revert OrderNotFound();
    if (order.seller != msg.sender) revert NotOrderSeller();
    if (!order.isActive) revert OrderAlreadyInactive();

    order.isActive = false;
    IERC20(order.tokenToSell).safeTransfer(order.seller, order.amountToSell);

    emit OrderCancelled(_orderId, order.seller);
}
```

**Risk**

*Likelihood*: High, due to seller inactivity over time
*Impact*: Tokens permanently locked + gas/storage bloat

**PoC**

```solidity
orderBook.createSellOrder(...); // seller loses access
// time passes...
orderBook.cancelSellOrder(orderId); // reverts for anyone except seller
```

**Mitigation**

```diff
- if (order.seller != msg.sender) revert NotOrderSeller();
+ if (order.seller != msg.sender && block.timestamp < order.deadlineTimestamp) revert NotOrderSeller();
```

This allows anyone to cancel expired orders and return tokens to sellers.

---

#### L-02. Uninitialized Local Variable Causes Empty Token Symbol in Order Details

**Root + Impact**

The `getOrderDetailsString()` function is meant to display order data including token symbol, but `tokenSymbol` is declared and never initialized. This causes the string to always return an empty token field.

```solidity
function getOrderDetailsString(uint256 _orderId) external view returns (string memory) {
    Order memory order = orders[_orderId];
    string memory tokenSymbol; // uninitialized

    string memory status;
    if (!order.isActive) {
        status = "Cancelled";
    } else if (order.isActive && block.timestamp >= order.deadlineTimestamp) {
        status = "Expired";
    } else if (block.timestamp < order.deadlineTimestamp) {
        status = "Active";
    }

    return string(abi.encodePacked(
        "Order ID: ", Strings.toString(_orderId),
        ", Token: ", tokenSymbol,
        ", Amount: ", Strings.toString(order.amountToSell),
        ", Price: ", Strings.toString(order.priceInUSDC),
        ", Status: ", status,
        ", Deadline: ", Strings.toString(order.deadlineTimestamp)
    ));
}
```

**PoC**

```solidity
string memory details = orderBook.getOrderDetailsString(1);
// Output: Token field is empty
```

**Mitigation**

```solidity
string memory tokenSymbol = "UNKNOWN";
try IERC20Metadata(order.tokenToSell).symbol() returns (string memory symbol) {
    if (bytes(symbol).length > 0) {
        tokenSymbol = symbol;
    }
} catch {
    tokenSymbol = Strings.toHexString(uint160(order.tokenToSell), 20);
}
```

This ensures meaningful output even if `symbol()` fails.


## Beatland Festival Protocol Audit — Codehawks

- **Dates:** July 15–22, 2025  
- **Scope:** 283 nSLOC  
- **Role:** Independent Auditor  
- **Rank:** Top 17 globally  
- **Contest:** [Beatland Festival Codehawks Page](https://codehawks.cyfrin.io/c/2025-07-beatland-festival)
-  **Submitted Full Reports:**
 - [High](https://codehawks.cyfrin.io/c/2025-07-beatland-festival/s/231)
 - [Medium](https://codehawks.cyfrin.io/c/2025-07-beatland-festival/s/26)
   
---

### Platform Vulnerabilities — Cyfrin Codehawks

* Repored a vulnerability in web platform for Codehawks
  [Acknowledged by Patrick Collions Sir](https://x.com/Ravenzbb/status/1946099361525710992)
  
Disclosed responsibly during live contests.

---

### Leaderboard

* Ranked [23rd globally](https://codehawks.cyfrin.io/leaderboard?page=3&r=1-month&sc=reward&sj=reward&t=contests) on Codehawks amongst Top 100 contest category for July 2025

---

### Certifications

* Cyfrin Web3 [Wallet Security Mastery Course](https://profiles.cyfrin.io/u/ishwar/achievements/web3-wallet-security-basics)
---

## Application Security Work

* Reported vulnerabilities in: Airtel, NASA, DRDO, Huawei, Nykaa, Blackberry, Siemens and lot more
* Platforms: Bugcrowd, HackerOne, Hackenproof, TryHackMe
* CVEs published: CVE-2025-25758, CVE-2025-25688, CVE-2025-25595
* Featured in NCIIPC Jan 2024 Newsletter (Top 15 security researchers)
* Google Hacking Database dork: [https://www.exploit-db.com/ghdb/8105](https://www.exploit-db.com/ghdb/8105)
* AIR 2 in FOSSx India (IIT Bombay)
* BlackHat Asia Bugcrowd CTF rank: 143
* Speaker at TenguCon Japan 2024
* CFP accepted at BSides Bloomington USA 2024
