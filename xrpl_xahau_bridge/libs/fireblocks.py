from fireblocks.client import Fireblocks
from fireblocks.client_configuration import ClientConfiguration
from fireblocks.base_path import BasePath
from fireblocks.models.create_wallet_request import CreateWalletRequest
from fireblocks.models.unmanaged_wallet import UnmanagedWallet
from fireblocks.client import Fireblocks
from fireblocks.client_configuration import ClientConfiguration
from fireblocks.exceptions import ApiException
from fireblocks.base_path import BasePath
from pprint import pprint


class FireblocksClient(object):
    fireblocks: Fireblocks = None

    def __init__(cls):
        configuration = ClientConfiguration(
            api_key="your_api_key",
            secret_key=secret_key_value,
            base_path=BasePath.Sandbox,  # or set it directly to a string "https://sandbox-api.fireblocks.io/v1"
        )
        with Fireblocks(configuration) as fireblocks:
            cls.fireblocks = fireblocks
            pass

    # TODO: DELETE/UPDATE/READ
    def create_external_wallet(cls, name: str, customer_ref_id: str):
        idempotency_key = "idempotency_key_example"
        create_wallet_request = cls.fireblocks.CreateWalletRequest(
            name=name,
            customer_ref_id=customer_ref_id,
        )
        try:
            api_response = cls.fireblocks.external_wallets.create_external_wallet(
                idempotency_key=idempotency_key,
                create_wallet_request=create_wallet_request,
            ).result()
            print("The response of ExternalWalletsApi->create_external_wallet:\n")
            pprint(api_response)
        except Exception as e:
            print(
                "Exception when calling ExternalWalletsApi->create_external_wallet: %s\n"
                % e
            )

    # TODO: DELETE/UPDATE/READ
    def add_asset_to_external_wallet(cls, classic_address: str, tag: str = None):
        wallet_id = "wallet_id_example"
        asset_id = "asset_id_example"
        idempotency_key = "idempotency_key_example" 
        add_asset_to_external_wallet_request = (
            cls.fireblocks.AddAssetToExternalWalletRequest(
                address=classic_address,
                tag=tag,
            )
        )
        try:
            api_response = cls.fireblocks.external_wallets.add_asset_to_external_wallet(
                wallet_id,
                asset_id,
                idempotency_key=idempotency_key,
                add_asset_to_external_wallet_request=add_asset_to_external_wallet_request,
            ).result()
            print("The response of ExternalWalletsApi->add_asset_to_external_wallet:\n")
            pprint(api_response)
        except Exception as e:
            print(
                "Exception when calling ExternalWalletsApi->add_asset_to_external_wallet: %s\n"
                % e
            )

    # TODO: DELETE/UPDATE/READ
    def create_asset_deposit_address(cls, description: str, customer_ref_id: str):
        vault_account_id = "vault_account_id_example"
        asset_id = "asset_id_example"
        idempotency_key = "idempotency_key_example"
        create_address_request = cls.fireblocks.CreateAddressRequest(
            description=description,
            customer_ref_id=customer_ref_id,
        )

        try:
            api_response = cls.fireblocks.vaults.create_vault_account_asset_address(
                vault_account_id,
                asset_id,
                idempotency_key=idempotency_key,
                create_address_request=create_address_request,
            ).result()
            print("The response of VaultsApi->create_vault_account_asset_address:\n")
            pprint(api_response)
        except Exception as e:
            print(
                "Exception when calling VaultsApi->create_vault_account_asset_address: %s\n"
                % e
            )
