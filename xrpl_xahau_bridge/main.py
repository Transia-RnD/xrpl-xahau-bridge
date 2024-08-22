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

xrpl_allowed_tts: List[str] = ["Payment", "NFTokenBurn"]
xahau_allowed_tts: List[str] = ["Payment", "URITokenBurn"]


async def bridge_payment_txn(txn: Dict[str, Any]):
    """
    Bridge a payment transaction.

    :param txn: The transaction to bridge.
    """
    to_xrpl = txn["OperationLimit"] == 0
    if to_xrpl:
        new_txn = Payment(
            account=txn["Destination"],
            destination=txn["Account"],
            amount=txn["Amount"],
        )
        xrpl_net = AsyncJsonRpcClient(os.environ.get("XRPL_RPC_URL"))
        wallet: Wallet = Wallet(os.environ.get("BRIDGE_ACCOUNT_SEED"), 0)
        prepared_txn = await autofill_and_sign(new_txn, wallet, xrpl_net)
        tx_response = await submit(prepared_txn, xrpl_net)
        if tx_response.result["engine_result"] != "tesSUCCESS":
            raise Exception(
                f"XRPL transaction failed: {tx_response.result['engine_result']}"
            )
        return
    else:
        new_txn = Payment(
            account=txn["Destination"],
            destination=txn["Account"],
            amount=txn["Amount"],
            network_id=int(os.environ.get("XAHAU_NETWORK_ID")),
        )
        xrpl_net = AsyncJsonRpcClient(os.environ.get("XAHAU_RPC_URL"))
        wallet: Wallet = Wallet(os.environ.get("BRIDGE_ACCOUNT_SEED"), 0)
        prepared_txn = await autofill_and_sign(new_txn, wallet, xrpl_net)
        tx_response = await submit(prepared_txn, xrpl_net)
        if (
            tx_response.result["engine_result"] != "tesSUCCESS"
            or tx_response.result["engine_result"] != "terQUEUED"
        ):
            raise Exception(
                f"XRPL transaction failed: {tx_response.result['engine_result']}"
            )
        return


async def bridge_txn(txn: Dict[str, Any]):
    """
    Bridge a transaction.

    :param txn: The transaction to bridge.
    """
    if txn["TransactionType"] == "Payment":
        await bridge_payment_txn(txn)
        return

    raise Exception("XPOP bridge transaction not implemented yet")


async def validate_xpop(xpop: Dict[str, Any], source: str) -> bool:
    """
    Validate an XPOP.

    :param xpop: The XPOP to validate.
    :param source: The source of the XPOP (xrpl or xahau).
    :return: True if the XPOP is valid, False otherwise.
    """
    vl_key: str = (
        os.environ.get("XRPL_UNL_KEY")
        if source == "xrpl"
        else os.environ.get("XAHAU_UNL_KEY")
    )
    account: str = os.environ.get("BRIDGE_ACCOUNT")

    transaction = xpop["transaction"]
    tx = xrpl.core.binarycodec.decode(transaction["blob"])
    if tx["Account"] != account and tx["Destination"] != account:
        return {"verified": False, "info": "Transaction not for bridge account"}

    if source == "xrpl":
        if tx["TransactionType"] not in xrpl_allowed_tts:
            return {"verified": False, "info": "Xrpl transaction type not allowed"}
    if source == "xahau":
        if tx["TransactionType"] not in xahau_allowed_tts:
            return {"verified": False, "info": "Xahau transaction type not allowed"}

    verification_result = verify(xpop, vl_key)

    if verification_result is False:
        return {
            "verified": False,
            "info": "Verification failed (tampering or damaged/incomplete/invalid data)",
        }
    else:
        return verification_result


async def process_file(file_path: str, source: str):
    """
    Asynchronously process a new file.

    :param file_path: The path to the file to process.
    """
    file_content: str = read_file(file_path)
    file_content = bytes.fromhex(file_content).decode("utf-8")
    file_content = json.loads(file_content)
    result: Dict[str, Any] = await validate_xpop(file_content, source)
    if result["verified"]:
        await bridge_txn(result["tx_blob"])

async def check_for_new_entries(folder_path: str, source: str, check_interval: int = 5):
    """
    Check a folder for new entries at regular intervals.

    :param folder_path: The path to the folder to monitor.
    :param check_interval: Time in seconds between checks.
    """
    previous_files = set(os.listdir(folder_path))

    try:
        while True:
            await asyncio.sleep(check_interval)
            current_files = set(os.listdir(folder_path))

            new_files = current_files - previous_files
            if new_files:
                await asyncio.gather(
                    *(
                        process_file(os.path.join(folder_path, file), source)
                        for file in new_files
                    )
                )

            previous_files = current_files

    except KeyboardInterrupt:
        print("Monitoring stopped.")
