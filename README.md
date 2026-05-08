AuditPilot2000
AuditPilot2000 is a Python-based security tool designed to identify and report configuration drift and security vulnerabilities in cloud environments. 
The project was developed as a practical application of my studies in Network and IT Security at Noroff University College, utilizing AI as a collaborative partner to accelerate development and problem-solving.   

🚀 Overview In modern cloud infrastructure, misconfigurations are a leading cause of security breaches. AuditPilot2000 automates the tedious process of auditing cloud settings against security best practices. This project demonstrates the intersection of Cloud Security, Python Programming, and AI-assisted Development.   

✨ Key FeaturesCloud Configuration Audit: Scans cloud environments for common security misconfigurations.   
Security Reporting: Generates clear insights into identified vulnerabilities.  
AI-Enhanced Logic: Leverages AI-optimized Python scripts for efficient data parsing and logic checks.   
Scalable Framework: Built with a modular structure, allowing for the addition of new audit rules.   

🛠️ Tech StackLanguage: Python   F
ocus Areas: Cloud Security (Azure/SaaS), Automation, and Infrastructure as Code (IaC) principles.   
Development Methodology: AI-Augmented Software Engineering.   

📖 How It WorksInput: The tool connects to designated cloud endpoints or configuration files.   
Analysis: Runs a series of audit modules based on security frameworks (inspired by SC-900 and AZ-900 curricula).   
Output: Provides a summary of risks, enabling proactive remediation before threats emerge.   

💡 About the ProjectThis tool is a testament to my proactive approach to learning. During my full-time studies while working 60-80% , I wanted to bridge the gap between theoretical network security and practical automation.  AuditPilot2000 shows my ability to:  
Identify complex technical problems.   
Learn and implement new programming languages (Python).   
Integrate AI tools into a professional workflow.   

# AuditPilot2000
Create a poor-mans Security Copilot
A security auditing tool for Azure resources with AI-driven remediation advice.

## Setup Instructions

1. **Environment Configuration**:
   - Create a .env file
   - Fill in your Azure Service Principal credentials and desired database password.

2. **Ollama (AI)**:
   - Ensure [Ollama](https://ollama.com/) is running on your host machine.
   - Download the model: `ollama run llama3.1:8b`.

3. **GUI Setup (Windows)**:
   - Install an X-Server (e.g., [VcXsrv](https://sourceforge.net/projects/vcxsrv/)).
   - Launch VcXsrv with "Disable access control" checked.
  
4. To save the output from the tool, a SQL database is needed. The original setup was made with MySQL.

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
