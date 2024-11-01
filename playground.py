
# import os
# import asyncio
# from xrpl_xahau_bridge.main import process_file, check_for_new_entries
from xrpl.wallet import Wallet

# os.environ['RPC_URL'] = 'https://xahau.network'
# os.environ['UNL_KEY'] = 'ED45D1840EE724BE327ABE9146503D5848EFD5F38B6D5FEDE71E80ACCE5E6E738B' # XRPL UNL
# os.environ['NETWORK_ID'] = '21337'

# # folder_to_monitor = 'xrpl/store/xpop'
# # asyncio.run(check_for_new_entries(folder_to_monitor))

# file_path = "xrpl/store/xpop/C0A994A4F1A58840FF88BC9188936DBC42DD63688112B8C465904D9C2B78C2D2"
# asyncio.run(process_file(file_path))


# rnhas9Edvx789NxvEq8MJhVttdTXKFqy5P
wallet = Wallet.from_seed("sEd7JWgbJmuiM4Aeumtr2GneCw22CnQ")
print(wallet)