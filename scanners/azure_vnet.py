import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

class Vnet_Scanner:
    def __init__(self, db_writer, ai_tool, log_func=None):
        load_dotenv()
        self.credential = DefaultAzureCredential()
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        self.db_writer = db_writer
        self.ai_tool = ai_tool
        self.log_func = log_func


    def log(self, message):
        """
        Helper to decide where to send text.
        """
        if self.log_func:
            self.log_func(message)
        else:
            print(message)
            
    def audit_vnet(self):
        pass