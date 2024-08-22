# XRPL XAHAU BRIDGE

## Setup Bridge

1. Add your bridge account/seed to the docker compose file.
2. Make sure the account is funded from both sides (XRPL & XAHAU)
2. Run the bridge

`docker compose -f ./docker-compose.yml up --build --force-recreate -d`

## Send From XRPL to Xahau

Submit the following transaction to the XRPL Ledger

```
{
  "TransactionType": "Payment",
  "Amount": "1000000",
  "Destination": "[YOUR_BRIDGE_ACCOUNT]",
  "OperationLimit": 21337
}
```

## Send From Xahau to XRPL

Submit the following transaction to the Xahau Ledger

```
{
  "TransactionType": "Payment",
  "Amount": "1000000",
  "Destination": "[YOUR_BRIDGE_ACCOUNT]",
  "OperationLimit": 0
}
```

## Supported Transactions

- Payment
- NFToken/URToken (Soon)

## Todo

- Add NFToke/URIToken Support
- Use Google KMS for the bridge account/seed
