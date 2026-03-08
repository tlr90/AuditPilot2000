import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient

class VM_scanner:
    """
    :load_dotenv(): This collects the credentials used to access Azure.
    :self.credential: Stores the Azure credentials.
    :self.subscription_id: Stores the Azure subscription id.
    :self.db_writer: This parameter is to pass the MySQL writer in to the script from the main script.
    :self.ai_tool: This parameter is to pass the AI tool in to the script from the main script.
    :self.log_func: This is the print function that passes the statements to the dashboard app.
    :self.network_client: The credentials used to access the NSGs in the subscription.
    """
    def __init__(self, db_writer, ai_tool, log_func=None):
        load_dotenv()
        self.credential = DefaultAzureCredential()
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        self.db_writer = db_writer
        self.ai_tool = ai_tool
        self.log_func = log_func
        self.network_client = NetworkManagementClient(self.credential, self.subscription_id)

    def log(self, message):
        """
        Helper to decide where to send text.
        This function helps send text to the dashboard app or terminal.
        """
        if self.log_func:
            self.log_func(message)
        else:
            print(message)

    def audit_vm(self):
        """
        The audit function. This is initialised from the main script. This will
        look at inbound rules in all the NSGs in the Azure environment. The function is that
        if an open port is found, the AI tool is consultet on the risk and remedy options.
        The findings are stored in the MySQL database.
        """
        self.log_func("--- Azure Security Audit: Virtual Machine Networking ---\n")

        try:
            nsgs = list(self.network_client.network_security_groups.list_all())

            if not nsgs:
                self.log_func("No NSGs found. Your network perimeter looks empty and secure.\n")
                return

            for nsg in nsgs:
                self.log_func(f"Checking NSG: {nsg.name}...\n")
                found_insecure = False

                for rule in nsg.security_rules:
                    if (
                        rule.access == "Allow" and
                        rule.direction == "Inbound" and
                        rule.source_address_prefix in ["*","0.0.0.0/0","Internet"]
                    ):
                        risky_ports = ["22","80","443","3389","*"]
                        dest_port = rule.destination_port_range
                        
                        if dest_port == "*" or any(p in dest_port for p in risky_ports):
                            self.log_func(f"Insecure rule found: {rule.name} (Port {rule.destination_port_range})\n")

                            # This prompt is sent to the AI tool for remidiation.
                            prompt_context = (
                                f"This is a Virtual Machine Network Security Group (NSG) audit. "
                                f"NSG Rule '{rule.name}' allows public access to port {rule.destination_port_range}. "
                                f"Explain the risk for a VM and provice the Azure CLI and Azure PowerShell fix. Short answer"
                            )
                            ai_advice = self.ai_tool.ask_ai_for_remidiation(prompt_context)

                            # Write the findings to the database, only insecure.
                            self.db_writer.save_vm_finding(nsg.name, 1, ai_advice)
                            self.log_func("Findings saved successfully!\n")
                        
                    else:
                        self.log_func(f"Rule {rule.name} looks okay\n")
                
                if not found_insecure:
                    self.log_func(f"NSG {nsg.name} has no high-risk public rules.\n")
        
        except Exception as e:
            self.log_func(f"Error when scanning VMs: {e}\n")

if __name__=="__main__":
    scanner = VM_scanner()
    scanner.audit_vm()