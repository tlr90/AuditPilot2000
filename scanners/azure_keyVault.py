import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault.secrets import SecretClient

class KeyVault_scanner:
    def __init__(self, db_writer, ai_tool, log_func=None):
        load_dotenv()
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        self.credential = DefaultAzureCredential()
        self.dbWriter = db_writer
        self.ai_tool = ai_tool
        self.log_func = log_func
        self.kv_mgmt_client = KeyVaultManagementClient(self.credential, self.subscription_id)

    def log(self, message):
        """
        Helper to decide where to send text.
        """
        if self.log_func:
            self.log_func(message)
        else:
            print(message)

    def audit_keyvaults(self):
        self.log_func("--- Azure Security Audit: Key Vault Secrets ---\n")

        try:
            vaults = list(self.kv_mgmt_client.vaults.list_by_subscription())

            if not vaults:
                self.log_func("No key vaults found. Your secrets are safe.\n")
                return

            for vault in vaults:
                self.log_func(f"Checking Vault: {vault.name}...\n")
                found_insecure = False

                vault_url = f"https://{vault.name}.vault.azure.net/"
                secret_client = SecretClient(vault_url=vault_url, credential=self.credential)

                secrets = secret_client.list_properties_of_secrets()

                for secret in secrets:
                    if not secret.expires_on:
                        self.log_func(f"Insecure: Secret '{secret.name}' has no expiration date.\n")

                        prompt = (
                            f"Azure Key Vault secret '{secret.name} has no expiration date set."
                            f"Explain shortly the security risk and provide the Azure CLI and Azure PowerShell command to set an expiry date."
                        )
                        ai_advice = self.ai_tool.ask_ai_for_remidiation(prompt)

                        self.dbWriter.save_keyVault_finding(vault.name, 1, ai_advice)
                        self.log_func("Findings saved successfully!\n")
                    else:
                        self.log_func(f"Secret '{secret.name}' is secure (Expires: {secret.expires_on})\n")
            
            if not found_insecure:
                self.log_func(f"Secret '{secret.name}' is secure (Expires: {secret.expires_on})\n")
        
        except Exception as e:
            self.log_func(f"Error when scanning Key Vaults: {e}\n")

if __name__=="__main__":
    scanner = KeyVault_scanner()
    scanner.audit_keyvaults()
