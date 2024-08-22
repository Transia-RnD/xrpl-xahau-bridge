
import asyncio
from xrpl_xahau_bridge.main import process_file, check_for_new_entries

# file_path = "xahau/store/xpop/DBBF5B4717340282DAD6A0B619B3C28124A007856B69D24D7F9826A2AE00E537"
# asyncio.run(process_file(file_path, 'xahau'))


folder_to_monitor = 'xrpl/store/xpop'
asyncio.run(check_for_new_entries(folder_to_monitor, source='xrpl'))