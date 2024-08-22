import sys
import json
import xrpl
import hashlib
from binascii import hexlify, unhexlify
import math
import base64

from typing import Dict, Any

def err(message):
    """Writes an error message to stderr."""
    sys.stderr.write("Error: " + message + "\n")
    return False

def process_validation_message(val):
    """
    Processes a validation message to extract the signing key, signature, 
    ledger hash, and the message without the signature.
    
    Args:
        val (str or bytes): The validation message in hex or bytes format.
    
    Returns:
        dict: A dictionary containing the extracted information or False on error.
    """
    if isinstance(val, str):
        val = unhexlify(val)

    upto = 0
    rem = len(val)
    ret = {}

    # Validate and extract fields from the validation message
    try:
        # Flags
        if val[upto] != 0x22 or rem < 5:
            return err("validation: sfFlags missing")
        upto += 5; rem -= 5

        # LedgerSequence
        if val[upto] != 0x26 or rem < 5:
            return err("validation: sfLedgerSequence missing")
        upto += 5; rem -= 5

        # CloseTime (optional)
        if val[upto] == 0x27:
            if rem < 5:
                return err("validation: sfCloseTime missing payload")
            upto += 5; rem -= 5

        # SigningTime
        if val[upto] != 0x29 or rem < 5:
            return err("validation: sfSigningTime missing")
        upto += 5; rem -= 5

        # LoadFee (optional)
        if val[upto] == 0x20 and rem >= 2 and val[upto+1] == 0x18:
            if rem < 6:
                return err("validation: sfLoadFee missing payload")
            upto += 6; rem -= 6

        # ReserveBase (optional)
        if val[upto] == 0x20 and rem >= 2 and val[upto+1] == 0x1F:
            if rem < 6:
                return err("validation: sfReserveBase missing payload")
            upto += 6; rem -= 6

        # ReserveIncrement (optional)
        if val[upto] == 0x20 and rem >= 2 and val[upto+1] == 0x20:
            if rem < 6:
                return err("validation: sfReserveIncrement missing payload")
            upto += 6; rem -= 6

        # BaseFee (optional)
        if val[upto] == 0x35:
            if rem < 9:
                return err("validation: sfBaseFee missing payload")
            upto += 9; rem -= 9

        # Cookie (optional)
        if val[upto] == 0x3A:
            if rem < 9:
                return err("validation: sfCookie missing payload")
            upto += 9; rem -= 9

        # ServerVersion (optional)
        if val[upto] == 0x3B:
            if rem < 9:
                return err("validation: sfServerVersion missing payload")
            upto += 9; rem -= 9

        # LedgerHash
        if val[upto] != 0x51 or rem < 33:
            return err("validation: sfLedgerHash missing")
        
        ret["ledger_hash"] = str(hexlify(val[upto+1:upto+33]), 'utf-8').upper()
        upto += 33; rem -= 32

        # ConsensusHash (optional)
        if val[upto] == 0x50 and rem >= 2 and val[upto+1] == 0x17:
            if rem < 34:
                return err("validation: sfConsensusHash payload missing")
            upto += 34; rem -= 34

        # ValidatedHash (optional)
        if val[upto] == 0x50 and rem >= 2 and val[upto+1] == 0x19:
            if rem < 34:
                return err("validation: sfValidatedHash payload missing")
            upto += 34; rem -= 34

        # SigningPubKey
        if val[upto] != 0x73 or rem < 3:
            return err("validation: sfSigningPubKey missing")

        keysize = val[upto+1]
        upto += 2; rem -= 2
        if keysize > rem:
            return err("validation: sfSigningPubKey incomplete")

        ret["key"] = str(hexlify(val[upto:upto+keysize]), 'utf-8').upper()
        upto += keysize; rem -= keysize

        # Signature
        sigstart = upto
        if val[upto] != 0x76 or rem < 3:
            return err("validation: sfSignature missing")
        
        sigsize = val[upto+1] 
        upto += 2; rem -= 2
        if sigsize > rem:
            return err("validation: sfSignature incomplete")
        
        ret["signature"] = val[upto:upto+sigsize]
        upto += sigsize; rem -= sigsize

        ret["without_signature"] = val[:sigstart] + val[upto:]

        return ret
    except Exception as e:
        return err(f"Error processing validation message: {str(e)}")

def make_vl_bytes(length):
    """
    Creates a variable length prefix for a XRPL serialized vl field.
    
    Args:
        length (int or float): The length to encode.
    
    Returns:
        bytes: The encoded length as bytes or False on error.
    """
    if isinstance(length, float):
        length = math.ceil(length)
    if not isinstance(length, int):
        return False
    if length <= 192:
        return bytes([length])
    elif length <= 12480:
        b1 = math.floor((length - 193) / 256 + 193)
        return bytes([b1, length - 193 - 256 * (b1 - 193)])
    elif length <= 918744:
        b1 = math.floor((length - 12481) / 65536 + 241)
        b2 = math.floor((length - 12481 - 65536 * (b1 - 241)) / 256)
        return bytes([b1, b2, length - 12481 - 65536 * (b1 - 241) - 256 * b2])
    else:
        return err("Cannot generate vl for length = " + str(length) + ", too large")

def sha512(data):
    """Returns the SHA-512 hash of the input data."""
    m = hashlib.sha512()
    m.update(data)
    return m.digest()

def sha512h(data):
    """Returns the first 32 bytes of the SHA-512 hash of the input data."""
    m = hashlib.sha512()
    m.update(data)
    return m.digest()[:32]

def hash_txn(txn):
    """
    Hashes a transaction.
    
    Args:
        txn (str or bytes): The transaction in hex or bytes format.
    
    Returns:
        bytes: The hashed transaction.
    """
    if isinstance(txn, str):
        txn = unhexlify(txn)
    return sha512h(b'TXN\x00' + txn)

def hash_txn_and_meta(txn, meta):
    """
    Hashes the transaction and its metadata as a leaf node in the shamap.
    
    Args:
        txn (str or bytes): The transaction in hex or bytes format.
        meta (str or bytes): The metadata in hex or bytes format.
    
    Returns:
        bytes: The hashed transaction and metadata.
    """
    if isinstance(txn, str):
        txn = unhexlify(txn)

    if isinstance(meta, str):
        meta = unhexlify(meta)

    vl1 = make_vl_bytes(len(txn))
    vl2 = make_vl_bytes(len(meta))
    
    if vl1 is False or vl2 is False:
        return False

    payload = b'SND\x00' + vl1 + txn + vl2 + meta + hash_txn(txn)
    return sha512h(payload).hex().upper()

def hash_ledger(idx, coins, phash, txroot, acroot, pclose, close, res, flags):
    """
    Hashes the ledger information.
    
    Args:
        idx (int): The ledger index.
        coins (int): The amount of coins.
        phash (bytes): The previous ledger hash.
        txroot (bytes): The transaction root.
        acroot (bytes): The account root.
        pclose (int): The previous close time.
        close (int): The close time.
        res (int): The reserve.
        flags (int): The flags.
    
    Returns:
        bytes: The hashed ledger.
    """
    if isinstance(idx, str):
        idx = int(idx)
    if isinstance(coins, str):
        coins = int(coins)
    if isinstance(phash, str):
        phash = unhexlify(phash)
    if isinstance(txroot, str):
        txroot = unhexlify(txroot)
    if isinstance(acroot, str):
        acroot = unhexlify(acroot)
    if isinstance(pclose, str):
        pclose = int(pclose)
    if isinstance(close, str):
        close = int(close)
    if isinstance(res, str):
        res = int(res)
    if isinstance(flags, str):
        flags = int(flags)

    if not all(isinstance(arg, int) for arg in [idx, coins, pclose, close, res, flags]):
        return err("Invalid int arguments to hash_ledger")

    idx = int.to_bytes(idx, byteorder='big', length=4)
    coins = int.to_bytes(coins, byteorder='big', length=8)
    pclose = int.to_bytes(pclose, byteorder='big', length=4)
    close = int.to_bytes(close, byteorder='big', length=4)
    res = int.to_bytes(res, byteorder='big', length=1)
    flags = int.to_bytes(flags, byteorder='big', length=1)

    if not all(isinstance(arg, bytes) for arg in [phash, txroot, acroot]):
        return err("Invalid bytes arguments to hash_ledger")

    payload = b'LWR\x00' + idx + coins + phash + txroot + acroot + pclose + close + res + flags
    return sha512h(payload)

def hash_proof(proof, depth=0):
    """
    Hashes a proof, which can be a list or a dictionary.
    
    Args:
        proof (list or dict): The proof to hash.
        depth (int): The current depth of recursion (used for internal purposes).
    
    Returns:
        bytes: The hashed proof.
    """
    if not isinstance(proof, (list, dict)):
        return err('Proof must be a list or dict')
    
    if isinstance(proof, list) and len(proof) < 16:
        return False

    hasher = hashlib.sha512()
    hasher.update(b'MIN\x00')

    if isinstance(proof, list):
        for i in range(16):
            if isinstance(proof[i], str):
                hasher.update(unhexlify(proof[i]))
            elif isinstance(proof[i], list):
                hasher.update(hash_proof(proof[i], depth + 1))
            else:
                return err("Unknown object in proof list")
    else:
        if 'children' in proof and len(proof['children']) > 0:
            for x in range(16):
                i = "0123456789ABCDEF"[x]
                if i not in proof['children']:
                    hasher.update(bytes(32))
                    continue
                h = hash_proof(proof['children'][i], depth + 1)
                hasher.update(h)
        elif 'hash' in proof:
            return unhexlify(proof['hash'])
        else:
            return err("Missing hash key in proof leaf")

    return hasher.digest()[:32]

def proof_contains(proof, h, depth = 0):
    """
    Checks if a proof contains a specific hash.
    
    Args:
        proof (list or dict): The proof to check.
        h (str or bytes): The hash to look for.
    
    Returns:
        bool: True if the hash is found, False otherwise.
    """

    if depth > 32:
        return False
    
    if not isinstance(proof, (list, dict)):
        return False

    if "children" in proof:
        return proof_contains(proof["children"], h, depth + 1)

    # if isinstance(h, str):
    #     h = unhexlify(h)

    for x in range(16):
        i = x
        if isinstance(proof, dict):
            i = "0123456789ABCDEF"[x]

        # should be if entry is null, continue
        if isinstance(proof[i], str) and proof[i] == "" or proof[i] is None or proof[i] == "0000000000000000000000000000000000000000000000000000000000000000":
            continue

        if (isinstance(proof[i], str) and proof[i] == h) or \
           ('hash' in proof[i] and proof[i]['hash'] == h) or \
           proof_contains(proof[i], h, depth + 1):
            return True

    return False

def verify(xpop: Dict[str, Any], vl_key: str):
    """
    Verifies a proof of payment (XPOP) against a validator list key.
    
    Args:
        xpop (str or dict): The proof of payment in JSON format or as a string.
        vl_key (str or bytes): The validator list key.
    
    Returns:
        dict: A dictionary containing verification results or False on failure.
    """

    if not isinstance(xpop, dict):
        return err("Expecting either a string or a dict")

    # Validate presence of required fields
    required_fields = ["ledger", "validation", "transaction"]
    for field in required_fields:
        if field not in xpop:
            return err(f"XPOP did not contain {field}")

    ledger = xpop["ledger"]
    validation = xpop["validation"]
    transaction = xpop["transaction"]

    if "unl" not in validation:
        return err("XPOP did not contain validation.unl")

    if "data" not in validation:
        return err("XPOP did not contain validation.data")

    unl = validation["unl"]
    data = validation["data"]

    if "public_key" not in unl:
        return err("XPOP did not contain validation.unl.public_key")

    if isinstance(vl_key, bytes):
        vl_key = hexlify(vl_key).upper()

    # Part A: Validate and decode UNL
    if vl_key.lower() != unl["public_key"].lower():
        return err("XPOP vl key is not one we recognize")

    # Extract and validate manifest and signature
    if "manifest" not in unl or "signature" not in unl:
        return err("XPOP did not contain validation.unl.manifest or validation.unl.signature")

    try:
        manifest = xrpl.core.binarycodec.decode(str(hexlify(base64.b64decode(unl["manifest"])), "utf-8"))
        signature = unhexlify(unl["signature"])
    except Exception:
        return err("XPOP invalid validation.unl.manifest (should be base64) or validation.unl.signature")

    if "MasterSignature" not in manifest or "Signature" not in manifest:
        return err("XPOP invalid validation.unl.manifest serialization")

    # Re-encode the manifest without signing fields
    manifestnosign = b'MAN\x00' + unhexlify(xrpl.core.binarycodec.encode_for_signing(manifest)[8:])

    # Check master signature
    if not xrpl.core.keypairs.is_valid_message(manifestnosign, unhexlify(manifest["MasterSignature"]), manifest["PublicKey"]):
        return err("XPOP vl signature validation failed")

    # Get UNL signing key
    signing_key = manifest["SigningPubKey"]

    # Validate UNL blob
    if "blob" not in unl:
        return err("XPOP invalid validation.unl.blob")

    payload = base64.b64decode(unl["blob"])

    # Check UNL blob signature
    if not xrpl.core.keypairs.is_valid_message(payload, unhexlify(unl["signature"]), signing_key):
        return err("XPOP invalid validation.unl.blob signature")

    # Decode UNL blob
    try:
        payload = json.loads(payload)
    except json.JSONDecodeError:
        return err("XPOP invalid validation.unl.blob json")

    # Validate UNL blob contents
    required_blob_fields = ["sequence", "expiration", "validators"]
    for field in required_blob_fields:
        if field not in payload:
            return err(f"XPOP missing validation.unl.blob.{field}")

    unlseq = payload["sequence"]
    unlexp = payload["expiration"]
    validators = {}
    validators_master_key = {}

    # Check UNL internal manifests and get validator signing keys
    for v in payload["validators"]:
        if "validation_public_key" not in v or "manifest" not in v:
            return err("XPOP missing validation_public_key or manifest from unl entry")

        try:
            manifest = base64.b64decode(v["manifest"])
            manifest = str(hexlify(manifest), "utf-8")
            manifest = xrpl.core.binarycodec.decode(manifest)
        except Exception:
            return err("XPOP invalid manifest in unl entry")

        if "MasterSignature" not in manifest or "SigningPubKey" not in manifest:
            return err("XPOP manifest missing master signature or signing key in unl entry")

        # Compute the node public address from the signing key
        nodepub = xrpl.core.addresscodec.encode_node_public_key(unhexlify(manifest["SigningPubKey"]))
        nodemaster = xrpl.core.addresscodec.encode_node_public_key(unhexlify(manifest["PublicKey"]))

        # Add the verified validator to the verified validator list
        validators[nodepub] = manifest["SigningPubKey"]
        validators_master_key[nodemaster] = nodepub

    # Part B: Validate TXN and META proof, and compute ledger hash
    computed_tx_hash_and_meta = hash_txn_and_meta(transaction["blob"], transaction["meta"])

    if not proof_contains(transaction["proof"], computed_tx_hash_and_meta):
        return err("Txn and meta were not present in provided proof")

    computed_tx_root = hash_proof(transaction["proof"])
    computed_ledger_hash = hash_ledger(ledger["index"], ledger["coins"], ledger["phash"], computed_tx_root, 
                                        ledger["acroot"], ledger["pclose"], ledger["close"], ledger["cres"], ledger["flags"])

    if computed_ledger_hash is False:
        return False

    computed_ledger_hash = str(hexlify(computed_ledger_hash), 'utf-8').upper()

    # Part C: Check validations to see if a quorum was reached on the computed ledger hash
    quorum = math.ceil(len(validators) * 0.8)
    votes = 0
    used_key = {}

    for nodepub in data:
        datakey = nodepub

        if nodepub in validators_master_key and validators_master_key[nodepub] in validators:
            used_key[nodepub] = True
            nodepub = validators_master_key[nodepub]

        if nodepub not in validators:
            continue
        
        if nodepub in used_key:
            continue

        used_key[nodepub] = True

        # Parse the validation message
        valmsg = process_validation_message(data[datakey])
        if valmsg is False:
            err("Warning: XPOP contained invalid validation from " + nodepub)
            continue

        # Check the signing key matches the key we have on file from the verified UNL
        if valmsg["key"] != validators[nodepub]:
            err("Warning: XPOP contained invalid KEY for validation from " + nodepub)
            continue
        
        # Check the ledger hash in the validation message matches the one we generated
        if valmsg["ledger_hash"] != computed_ledger_hash:
            continue
        
        # Check the signature on the validation message
        valpayload = b'VAL\x00' + valmsg["without_signature"]
        if not xrpl.core.keypairs.is_valid_message(valpayload, valmsg["signature"], valmsg["key"]):
            err("Warning: XPOP contained validation with invalid signature")
            continue

        # If all is well, the successfully verified validation message counts as a vote toward quorum
        votes += 1

    # Part D: Return useful information to the caller
    if votes < quorum:
        return False

    try:
        tx = xrpl.core.binarycodec.decode(transaction["blob"])
        meta = xrpl.core.binarycodec.decode(transaction["meta"])
    except Exception as e:
        return err("Error decoding txblob and meta")

    ret = {
        "verified": True,
        "tx_blob": tx,
        "tx_meta": meta,
        "ledger_hash": computed_ledger_hash,
        "ledger_index": ledger["index"],
        "ledger_unixtime": xrpl.utils.ripple_time_to_posix(ledger["close"]),
        "validator_quorum": quorum,
        "validator_count": len(validators),
        "validator_votes": votes,
        "vl_master_key": vl_key,
        "vl_expiration_unixtime": xrpl.utils.ripple_time_to_posix(unlexp),
        "vl_sequence": unlseq,
        "tx_source": tx["Account"],
    }

    if "InvoiceID" in tx:
        ret["tx_invoice_id"] = tx["InvoiceID"]

    ret["tx_is_payment"] = tx["TransactionType"] == "Payment"

    if "DestinationTag" in tx:
        ret["tx_destination_tag"] = tx["DestinationTag"]

    if "Destination" in tx:
        ret["tx_destination"] = tx["Destination"]
        # Search the meta for the modified nodes and construct a delivered amount field for XRP payments
        if "AffectedNodes" in meta:
            for af in meta["AffectedNodes"]:
                if "ModifiedNode" in af:
                    mn = af["ModifiedNode"]
                    if ("FinalFields" in mn and "PreviousFields" in mn and 
                        mn["LedgerEntryType"] == "AccountRoot" and 
                        "Account" in mn["FinalFields"] and 
                        mn["FinalFields"]["Account"] == tx["Destination"] and 
                        "Balance" in mn["PreviousFields"] and 
                        "Balance" in mn["FinalFields"]):
                        ret["tx_delivered_drops"] = \
                            int(mn["FinalFields"]["Balance"]) - int(mn["PreviousFields"]["Balance"])
                        break

    return ret