
import os
import asyncio
from xrpl_xahau_bridge.main import check_for_new_entries



if __name__ == "__main__":
    try:
        print('Starting the bridge...')
        folder_to_monitor = os.environ.get('FOLDER_PATH')
        asyncio.run(check_for_new_entries(folder_to_monitor))
    except Exception as e:
        print(e)