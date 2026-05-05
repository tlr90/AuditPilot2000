import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
# from azure.mgmt.resource import ResourceManagementClient

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
        self.log_func("--- Azure Security Audit: Azure VNET ---\n")
        try:
            network_client = NetworkManagementClient(self.credential, self.subscription_id)
            # Check for risky open ports
            for nsg in network_client.network_security_groups.list_all():
                for rule in nsg.security_rules:
                    if rule.access == "Allow" and rule.direction == "Inbound":
                        if rule.source_address_prefix == "*" or rule.source_address_prefix == "0.0.0.0/0":
                            if rule.destination_port_range in ["22","3389","445","3306"]:
                                prompt = (
                                    f"STRICT INSTRUCTIONS! Analyze Network Security Group named {nsg.name}. "
                                    "This NSG has open ports. Shortly explain the security risk. "
                                    "Provide the specific Azure CLI/Powershell to mitigate this."
                                )
                                ai_advice = self.ai_tool.ask_ai_for_remidiation(prompt)
                                self.db_writer(nsg.name, 5, ai_advice)
                                self.log_func("Findings saved successfully!\n")
            
            # Check for active VNETs and associated network security groups
            vnets = network_client.virtual_networks.list_all()
            for vnet in vnets:
                for subnet in vnet.subnets:
                    if subnet.network_security_group is None:
                        prompt = (
                            f"STRICT INSTRUCTIONS! Analyze VNET named {vnet.name}. "
                            "This VNET has no security group assigned. Shortly explain the security risk. "
                            "Provide the specific Azure CLI/Powershell to mitigate this."
                        )            
                        ai_advice = self.ai_tool.ask_ai_for_remidiation(prompt)
                        self.db_writer(vnet.name, 5, ai_advice)
                        self.log_func("Findings saved successfully!\n")

            # Check for network peerings
            for vnet in vnets:
                if vnet.virtual_network_peerings:
                    for peering in vnet.virtual_network_peerings:
                        if peering.allow_forwarded_traffic:
                            prompt(
                                f"STRICT INSTRUCTIONS! Analyze VNET named {vnet.name}. "
                                "This VNET has network peering active. Shortly explain the security risk. "
                                "Provide the specific Azure CLI/Powershell to mitigate this."
                            )
                            ai_advice = self.ai_tool.ask_ai_for_remidiation(prompt)
                            self.db_writer(vnet.name, 5, ai_advice)
                            self.log_func("Findings saved successfully!\n")
            
            # Scan network interface cards for public facing IP addresses
            nics = network_client.network_interfaces.list_all()
            for nic in nics:
                for config in nic.ip_configurations:
                    if config.public_ip_address:
                        prompt = (
                            f"STRICT INSTRUCTIONS! Analyze VNET named {nic.name}. "
                            "This NIC has public facing IP address. Shortly explain the security risk. "
                            "Provide the specific Azure CLI/Powershell to mitigate this."
                        )
                        ai_advice = self.ai_tool.ask_ai_for_remidiation(prompt)
                        self.db_writer(nic.name, 5, ai_advice)
                        self.log_func("Findings saved successfully!\n")
        except Exception as e:
            self.log_func(f"Error: {e}")

if __name__=="__main__":
    scanner = Vnet_Scanner()
    scanner.audit_vnet()