
import os
import asyncio
from xrpl_xahau_bridge.main import process_file, check_for_new_entries

os.environ['RPC_URL'] = 'https://xahau.network'
os.environ['UNL_KEY'] = 'ED45D1840EE724BE327ABE9146503D5848EFD5F38B6D5FEDE71E80ACCE5E6E738B' # XRPL UNL
os.environ['NETWORK_ID'] = '21337'

folder_to_monitor = 'xrpl/store/xpop'
asyncio.run(check_for_new_entries(folder_to_monitor))