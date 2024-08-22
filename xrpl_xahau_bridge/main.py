import os
import sys
import json
import asyncio
from typing import Any, Dict, List

import xrpl
from xrpl.asyncio.clients import AsyncJsonRpcClient
from xrpl.wallet import Wallet
from xrpl.asyncio.transaction import submit, autofill_and_sign
from xrpl.models.transactions import Payment

from xrpl_xahau_bridge.utils import read_file
from xrpl_xahau_bridge.xpop import verify
from dotenv import load_dotenv

load_dotenv()

allowed_tts: List[str] = ["Payment", "NFTokenBurn", "URITokenBurn"]


async def bridge_payment_txn(txn: Dict[str, Any]):
    """
    Bridge a payment transaction.

    :param txn: The transaction to bridge.
    """
    print(f"Bridging payment transaction: {txn}")
    to_xrpl = txn["OperationLimit"] == 0
    if to_xrpl:
        print("Sending transaction to XRPL")
        new_txn = Payment(
            account=txn["Destination"],
            destination=txn["Account"],
            amount=txn["Amount"],
        )
        xrpl_net = AsyncJsonRpcClient(os.environ.get("RPC_URL"))
        wallet: Wallet = Wallet(os.environ.get("BRIDGE_ACCOUNT_SEED"), 0)
        prepared_txn = await autofill_and_sign(new_txn, wallet, xrpl_net)
        tx_response = await submit(prepared_txn, xrpl_net)
        print(f"XRPL transaction response: {tx_response.result}")
        if tx_response.result["engine_result"] != "tesSUCCESS":
            raise Exception(
                f"XRPL transaction failed: {tx_response.result['engine_result']}"
            )
        print("Transaction successfully sent to XRPL")
        return
    else:
        print("Sending transaction to Xahau")
        new_txn = Payment(
            account=txn["Destination"],
            destination=txn["Account"],
            amount=txn["Amount"],
            network_id=int(os.environ.get("NETWORK_ID")),
        )
        xrpl_net = AsyncJsonRpcClient(os.environ.get("RPC_URL"))
        wallet: Wallet = Wallet(os.environ.get("BRIDGE_ACCOUNT_SEED"), 0)
        prepared_txn = await autofill_and_sign(new_txn, wallet, xrpl_net)
        tx_response = await submit(prepared_txn, xrpl_net)
        print(f"Xahau transaction response: {tx_response.result}")
        if (
            tx_response.result["engine_result"] != "tesSUCCESS"
            and tx_response.result["engine_result"] != "terQUEUED"
        ):
            raise Exception(
                f"Xahau transaction failed: {tx_response.result['engine_result']}"
            )
        print("Transaction successfully sent to Xahau")
        return


async def bridge_txn(txn: Dict[str, Any]):
    """
    Bridge a transaction.

    :param txn: The transaction to bridge.
    """
    print(f"Bridging transaction: {txn}")
    if txn["TransactionType"] == "Payment":
        await bridge_payment_txn(txn)
        return

    raise Exception("XPOP bridge transaction not implemented yet")


async def validate_xpop(xpop: Dict[str, Any]) -> bool:
    """
    Validate an XPOP.

    :param xpop: The XPOP to validate.
    :return: True if the XPOP is valid, False otherwise.
    """
    print(f"Validating XPOP")
    vl_key: str = os.environ.get("UNL_KEY")
    account: str = os.environ.get("BRIDGE_ACCOUNT")

    transaction = xpop["transaction"]
    tx = xrpl.core.binarycodec.decode(transaction["blob"])
    if tx["Account"] != account and tx["Destination"] != account:
        print("Transaction not for bridge account")
        return {"verified": False, "info": "Transaction not for bridge account"}

    if tx["TransactionType"] not in allowed_tts:
        print("Transaction type not allowed")
        return {"verified": False, "info": "Transaction type not allowed"}

    verification_result = verify(xpop, vl_key)

    if verification_result is False:
        print("Verification failed (tampering or damaged/incomplete/invalid data)")
        return {
            "verified": False,
            "info": "Verification failed (tampering or damaged/incomplete/invalid data)",
        }
    else:
        print("XPOP verification successful")
        return verification_result


async def process_file(file_path: str):
    """
    Asynchronously process a new file.

    :param file_path: The path to the file to process.
    """
    print(f"Processing file: {file_path}")
    file_content: str = read_file(file_path)
    file_content = bytes.fromhex(file_content).decode("utf-8")
    file_content = json.loads(file_content)
    result: Dict[str, Any] = await validate_xpop(file_content)
    if result["verified"]:
        print("XPOP verified, bridging transaction")
        await bridge_txn(result["tx_blob"])
    else:
        print(f"XPOP validation failed: {result['info']}")


async def check_for_new_entries(folder_path: str, check_interval: int = 5):
    """
    Check a folder for new entries at regular intervals.

    :param folder_path: The path to the folder to monitor.
    :param check_interval: Time in seconds between checks.
    """
    print(f"Monitoring folder: {folder_path} for new entries")
    previous_files = set(os.listdir(folder_path))

    try:
        while True:
            await asyncio.sleep(check_interval)
            current_files = set(os.listdir(folder_path))

            new_files = current_files - previous_files
            if new_files:
                print(f"New files detected: {new_files}")
                await asyncio.gather(
                    *(
                        process_file(os.path.join(folder_path, file))
                        for file in new_files
                    )
                )

            previous_files = current_files

    except KeyboardInterrupt:
        print("Monitoring stopped.")