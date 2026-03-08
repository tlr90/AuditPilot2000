import requests
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential

class User_scanner:
    def __init__(self, db_writer, ai_tool, log_func=None):
        load_dotenv()
        self.db_writer = db_writer
        self.ai_tool = ai_tool
        self.log_func = log_func
        self.credential = DefaultAzureCredential()
        self.token = self.credential.get_token("https://graph.microsoft.com/.default").token
        self.headers = {"Authorization":f"Bearer {self.token}"}

    def audit_users(self):
        insecure_users = []
        self.log_func("--- Azure Security Audit: User Identity and MFA ---\n")

        url = "https://graph.microsoft.com/v1.0/users"
        try:
            response = requests.get(url, headers=self.headers)
            users = response.json().get('value',[])

            for user in users:
                display_name = user.get('displayName')
                user_id = user.get('id')

                auth_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/authentication/methods"
                auth_res = requests.get(auth_url, headers=self.headers)
                methods = auth_res.json().get('value',[])

                if not methods:
                    insecure_users.append(user.get('displayName'))
                else:
                    self.log_func(f"User {display_name} has MFA registered.\n")

            if insecure_users:
                self.log_func(f"Found {len(insecure_users)} users without MFA. Requesting batch advice\n")
        
                list_str = ", ".join(insecure_users)
                prompt = (
                    f"I found {len(insecure_users)} users without MFA enabled: {list_str}. "
                    f"Provide a short risk summary (2 sentences) and the Azure CLI/PowerShell commands"
                    f"to enforce MFA or Conditional Access for these users. "
                    f"Keep it concise and do not address users by name in the response."
                )
                
                ai_advice = self.ai_tool.ask_ai_for_remidiation(prompt)

                self.log_func("\nSaving result to database...\n")
                for name in insecure_users:
                    self.db_writer.save_user_finding(name, 1, ai_advice)
                self.log_func(f"Done. Saved {len(insecure_users)} individual audit rows.\n")
                self.log_func("Findings saved successfully!\n")
            else:
                self.log_func("\nNo insecure users found. Database not updated.\n")

        except Exception as e:
            self.log_func(f"Error when scanning users: {e}\n")
        except KeyboardInterrupt:
            self.log_func("Stopping scan...\n")
    
    def log(self, message):
        """
        Helper to decide where to send text.
        """
        if self.log_func:
            self.log_func(message)
        else:
            print(message)

if __name__=="__main__":
    scanner = User_scanner()
    scanner.audit_users()