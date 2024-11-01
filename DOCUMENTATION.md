1. Configure the Issuer Account

1. Install `xpop_iou_iou` hook on Issuer account on Xahau.

- iou iou hook will be configured to read an XRP transfer to a specific account. It will read the amount delivered. It will then mint, wXRP on the Xahau chain though the hook and deliver to the account that sent the funds. 


Flow (XRP -> wXRP):

User Registers for service. Account is whitelisted in fireblocks.

- create user (Server)
- create user external wallet (Fireblocks)
- add asset to external wallet (Fireblocks)
- create user deposit tag (Fireblocks)

User sends funds to custody account w/ dest tag (SIGNATURE #1)

```json
{
  "TransactionType": "Payment",
  "Account": "rnhas9Edvx789NxvEq8MJhVttdTXKFqy5P", // Whitelisted User Address
  "Destination": "rfaBmnj28WMGfhvEbLjCnw6PEcZdoE85ra",
  "DestinationTag": 197849667,  // Whitelisted User DestTag
  "Amount": "1",  // Amount in drops
  "OperationLimit": 21337
}
```

XPOP is generated. Account is activated on Xahau if not exists. User is verified in Fireblocks (KYC/AML)

User submits XPOP to Xahau. (SIGNATURE #2)

Issuer account issues wXRP.

Flow (wXRP -> XRP)

User sends funds to custody account w/ dest tag

```json
{
  "TransactionType": "Payment",
  "Account": "rnhas9Edvx789NxvEq8MJhVttdTXKFqy5P", // Whitelisted User Address
  "Destination": "rfaBmnj28WMGfhvEbLjCnw6PEcZdoE85ra",
  "DestinationTag": 197849667,  // Whitelisted User DestTag
  "Amount": "1",  // Amount in drops
  "OperationLimit": 21337
}
```

XPOP is generated. User Fireblocks Account is looked up. Verified. (AML/KYC)

XPOP is verified (Internally/Server Function)

Fireblocks Transaction is created: Amount/Dest is taken from the XPOP.

```json
{
  "TransactionType": "Payment",
  "Account": "rfaBmnj28WMGfhvEbLjCnw6PEcZdoE85ra", // Whitelisted User Address
  "Destination": "rnhas9Edvx789NxvEq8MJhVttdTXKFqy5P",
  "Amount": "1" // Amount in drops
}
```

- fireblocks documentation: https://developers.fireblocks.com/reference/api-overview