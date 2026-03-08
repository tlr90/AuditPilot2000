import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

class Storage_scanner:
    """
    Docstring for Storage_scanner

    This is a scanner tool to make sure Azure storage is not facing public domain.
    The tool accesses the online storage account through a service principle and checks if the 
    resource is safe. More attributes can be checked by adding more getattr().
    The script connects to a local llama3.1:8b model to prevent online exposure.
    All the information gathered from the scan is written to a local MySQL db.
    """

    def __init__(self, db_writer, ai_tool, log_func=None):
        """
        :load.dotenv(): Fetch the credentials from the .env file
        :self.subscription_id: Stores the subscription ID from the .env file in a variable
        :self.credential: Stores the subscription credential from the .env file in a variable
        :self.ai_tool: Creates the AI analyzing tool
        :self.dbWriter: Creates the writing tool that connects and executes to MySQL db.
        :self.log_func: This is the print function that passes the statements to the dashboard app.
        """
        load_dotenv()
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        self.credential = DefaultAzureCredential()
        self.ai_tool = ai_tool
        self.dbWriter = db_writer
        self.log_func = log_func
    
    def log(self, message):
        """
        Helper to decide where to send text.
        This function helps send text to the dashboard app or terminal.
        """
        if self.log_func:
            self.log_func(message)
        else:
            print(message)

    def audit_storage(self):
        """
        Docstring for audit_storage
        Used to create access through service principal as a reader role to prevent misconfigured
        storage resources. 
        """
        self.log_func("--- Azure Security Audit: Storage Accounts ---\n")

        try:
            # Access the storage in Azure, setting up a client varable.
            storage_client = StorageManagementClient(self.credential, self.subscription_id)
            accounts = list(storage_client.storage_accounts.list())

            if not accounts:
                self.log_func("No storage accounts found in this subscription.\n")
                return
            # Add more getattr() here to make the script check for other features/safety.
            # If more is added, the prompt needs to be altered.
            # This checks for public access to the blob
            for account in accounts:
                is_public = getattr(account, 'allow_blob_public_access', False)

                if is_public:
                    self.log_func(f"Account {account.name:25} | Status: Insecure\n")
                    
                    # Prompt sent to the AI tool for advice and command fixes.
                    prompt = (
                        f"STRICT INSTRUCTION: Analyze the Azure Storage Account named '{account.name}'. "
                        f"This account has Public Access enabled. Explain the security risk of "
                        f"anonymous access and provice the specific Azure CLI/Powershell to disable it. "
                        f"Do not define the name of the account; provide only security advice."
                    )
                    ai_advice = self.ai_tool.ask_ai_for_remidiation(prompt)
                    
                    # Write the findings to the database. Only insecure findings.
                    self.dbWriter.save_storage_finding(account.name, 1, ai_advice)
                    self.log_func("Findings saved successfully!\n")
                
                else:
                    self.log_func(f"Account: {account.name:25} | Status: Secure\n")

        except Exception as e:
            self.log_func(f"Error: {e}\n") 

if __name__ == "__main__":
    scanner = Storage_scanner()
    scanner.audit_storage()