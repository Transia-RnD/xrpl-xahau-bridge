
from binascii import unhexlify
from typing import Dict, Any
from xrpl.core.addresscodec import encode_classic_address

def read_file(file_path: str):
    with open(file_path, 'r') as file:
        return file.read()

def has_forward_id(memos: list):
    for memo in memos:
        if 'Memo' in memo and 'MemoFormat' in memo['Memo'] and memo['Memo']['MemoFormat'] == '666F72776172642F6163636F756E746964':
            return encode_classic_address(bytes.fromhex(memo['Memo']['MemoData']))
        

def is_invoke(txn: Dict[str, Any], memos: list):
    if txn['TransactionType'] == 'Payment' and txn['Amount'] == '1':
        for memo in memos:
            if 'Memo' in memo and 'MemoFormat' in memo['Memo'] and memo['Memo']['MemoFormat'] == '74742F696E766F6B65':
                return True

    return False

def get_hook_parameters(memos: list):
    hook_parameters = []
    for memo in memos:
        if 'Memo' in memo and 'MemoFormat' in memo['Memo']:
            if unhexlify(memo['Memo']['MemoFormat']).decode('utf-8').split('/')[0] == 'param':
                hook_parameters.append({
                    'HookParameterName': memo['Memo']['MemoFormat'].split('706172616D2F')[1],
                    'HookParameterValue': memo['Memo']['MemoData'],
                })
    return hook_parameters