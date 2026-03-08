import os
import mysql.connector as mySQL
from dotenv import load_dotenv

class MySQL_Writer:
    """
    Docstring for MySQL_Writer

    This tool takes input from the storage, vm, nsg, and user scanner and saves it to a
    local MySQL db.
    The credentials is saved in a local configuration file.
    The insert is the same for all scanners, so the script is the same but called depending on the resource scanned.
    """
    def __init__(self, log_func=None):
        """
        Docstring for __init__
        
        :param self.config: Stores the credentials from the local config file.
        :param self.log_func: Function to print text to the dashboard GUI 
        """
        load_dotenv()
        self.log_func = log_func
        self.DB_CONFIG = {
            "host":os.getenv("DB_HOST", "localhost"),
            "database":os.getenv("DB_NAME"),
            "user":os.getenv("DB_USER"),
            "password":os.getenv("DB_PASSWORD")
            # "port":os.getenv("DB_PORT") # Initiate this when in Docker container. Remember to remove comment in .env.
        }

    def log(self, message):
        """
        Helper to decide where to send text.
        """
        if self.log_func:
            self.log_func(message)
        else:
            print(message)

    def execute_query(self, resource_name, type_id, status_id, ai_text):
        conn = None
        try:
            conn = mySQL.connect(**self.DB_CONFIG)
            cursor = conn.cursor()

            sql = "INSERT INTO security_findings (resource_name, type_id, status_id, ai_remediation_text) VALUES (%s,%s,%s,%s)"
            values = (resource_name, type_id, status_id, ai_text)

            cursor.execute(sql, values)
            conn.commit()

        except mySQL.Error as err:
            self.log_func(f"Database error: {err}\n")
        finally:
            if "conn" in locals() and conn.is_connected():
                cursor.close()
                conn.close()

    def save_storage_finding(self, name, status_id, ai_text):
        self.execute_query(name, 1, status_id, ai_text)
    
    def save_vm_finding(self, name, status_id, ai_text):
        self.execute_query(name, 2, status_id, ai_text)
    
    def save_user_finding(self, name, status_id, ai_text):
        self.execute_query(name, 3, status_id, ai_text)

    def save_keyVault_finding(self, name, status_id, ai_text):
        self.execute_query(name, 4, status_id, ai_text)

    def fetch_filtered_findings(self, search_text="", resource_type=None, date_range="All Time"):
        conn = None

        try:
            conn = mySQL.connect(**self.DB_CONFIG)
            cursor = conn.cursor()

            query = "SELECT id, resource_name, type_id, ai_remediation_text, detected_at FROM security_findings WHERE 1=1"
            params = []

            # Free search. Name or advice.
            if search_text:
                query += " AND (resource_name LIKE %s OR ai_remediation_text LIKE %s)"
                params.append([f"%{search_text}%", f"%{search_text}%"])

            # Search by resource type
            type_map = {
                "Storage": 1,
                "VM": 2,
                "Users": 3,
                "KeyVault": 4
                }
            if resource_type and resource_type != "All Types":
                mapped_id = type_map.get(resource_type)
                if mapped_id:
                    query += " AND type_id = %s"
                    params.append(mapped_id)

            # Search by date ranges
            if date_range == "Today":
                query += " AND detected_at >= CURDATE()"
            elif date_range == "Last 7 Days":
                query += " AND detected_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
            elif date_range == "Last 30 Days":
                query += " AND detected_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)"

            query += " ORDER BY detected_at DESC"

            cursor.execute(query, params or ())
            return cursor.fetchall()
        
        except Exception as e:
            
            self.log_func(f"Database error: {e}")
            return []
        
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()