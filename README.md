# AuditPilot2000
Create a poor-mans Security Copilot

# AzurePilot Auditor

A security auditing tool for Azure resources with AI-driven remediation advice.

## Setup Instructions

1. **Environment Configuration**:
   - Rename `.env.example` to `.env`.
   - Fill in your Azure Service Principal credentials and desired database password.

2. **Ollama (AI)**:
   - Ensure [Ollama](https://ollama.com/) is running on your host machine.
   - Download the model: `ollama run llama3.1:8b`.

3. **GUI Setup (Windows)**:
   - Install an X-Server (e.g., [VcXsrv](https://sourceforge.net/projects/vcxsrv/)).
   - Launch VcXsrv with "Disable access control" checked.

4. **Launch via Docker**:
   ```bash
   docker-compose up --build

5. **Script for Service Principal**:
Make sure that Azure CLI is installed locally.
PowerShell: winget install - -exact - -id Microsoft.AzureCLI
Install wizard: https://aka.ms/installazurecliwindowsx64 

Then run az login. Follow the prompts.

Now you are ready to run this script.
# 1. Get your Subscription ID
$SUBSCRIPTION_ID=$(az account show --query id -o tsv)

# 2. Create the Service Principal with Reader access
# Replace 'AzurePilotAuditor' with your preferred name
az ad sp create-for-rbac --name "AzurePilotAuditor" \
                         --role "Reader" \
                         --scopes "/subscriptions/$SUBSCRIPTION_ID" \
                         --sdk-auth

After the script has ran, insert the output you get into the .env file in correct placements.
