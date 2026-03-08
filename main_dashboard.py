import customtkinter as ctk
import threading
import csv
from tkinter import messagebox
from tkinter import filedialog
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
from core.db_writer import MySQL_Writer
from core.ai_tool import AI_Analyzer
from scanners.azure_storage import Storage_scanner
from scanners.azure_vm import VM_scanner
from scanners.azure_keyVault import KeyVault_scanner
from scanners.azure_users import User_scanner
from scanners.azure_vnet import Vnet_Scanner

class AzurePilotApp(ctk.CTk):
    last_message_ended_with_newline = True

    def __init__(self):
        super().__init__()

        self.title("AzurePilot Security Dashboard")
        self.geometry("1100x600")
        ctk.set_appearance_mode("dark")
    
        self.db = MySQL_Writer(log_func=self.log_message)
        self.ai = AI_Analyzer(log_func=self.log_message)

        self.storage_tool = Storage_scanner(self.db, self.ai, log_func=self.log_message)
        self.vm_tool = VM_scanner(self.db, self.ai, log_func=self.log_message)
        self.keyVault_tool = KeyVault_scanner(self.db, self.ai, log_func=self.log_message)
        self.user_tool = User_scanner(self.db, self.ai, log_func=self.log_message)
        self.vnet_tool = Vnet_Scanner(self.db, self.ai, log_func=self.log_message)

        self.setup_ui()

        self.stop_requested = False

    # Setup for the dashboard
    def setup_ui(self):
        # Grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(6, weight=1)

        # Sidebar frame
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="AZURE PILOT", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Scanner buttons
        self.btn_storage = ctk.CTkButton(self.sidebar_frame, text="Scan Storage", command=lambda: self.start_scan("storage"))
        self.btn_storage.grid(row=1, column=0, padx=20, pady=10)

        self.btn_vm = ctk.CTkButton(self.sidebar_frame, text="Scan VMs/NSG", command=lambda: self.start_scan("vm"))
        self.btn_vm.grid(row=2, column=0, padx=20, pady=10)

        self.btn_users = ctk.CTkButton(self.sidebar_frame, text="Scan Entra ID", command=lambda: self.start_scan("users"))
        self.btn_users.grid(row=3, column=0, padx=20, pady=10)

        self.btn_keyvault = ctk.CTkButton(self.sidebar_frame, text="Scan KeyVault", command=lambda: self.start_scan("keyvault"))
        self.btn_keyvault.grid(row=4, column=0, padx=20, pady=10)
        
        self.btn_vnet = ctk.CTkButton(self.sidebar_frame, text="Scan Vnet", command=lambda: self.start_scan("vnet"))
        self.btn_vnet.grid(row=5, column=0, padx=20, pady=10)

        # Button for database window
        self.btn_db = ctk.CTkButton(self.sidebar_frame, text="View Findings", command=self.open_findings_window)
        self.btn_db.grid(row=6, column=0, padx=20, pady=10)
        
        # Stop button
        self.btn_stop = ctk.CTkButton(self.sidebar_frame, text="Stop scan", fg_color="firebrick", hover_color="darkred", command=self.request_stop)
        self.btn_stop.grid(row=7, column=0, padx=20, pady=20)

        # Theme toggle
        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text="Theme:", anchor="w")
        self.appearance_mode_label.grid(row=8, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionmenu = ctk.CTkOptionMenu(self.sidebar_frame, values=["Dark","Light","System"], command=self.change_appearance_mode)
        self.appearance_mode_optionmenu.grid(row=9, column=0, padx=20, pady=(10, 0))

        # Main content area
        self.log_textbox = ctk.CTkTextbox(self, width=700, font=("Consolas", 12))
        self.log_textbox.grid(row=0, column=1, padx=(20, 20), pady=(20, 20), sticky="nsew")

        # Welcome message
        self.log_message("System initialized. Cloud connectivity confirmed.\n")

    # Stop button function
    def request_stop(self):
        self.stop_requested = True
        self.log_message("Stop requested. Finishing current task and exiting..\n")
    
    # Smart message printer to textbox
    def log_message(self, message, force_line=True, **kwargs):
        """
        Helper to write the UI textbox instead of just the terminal.
        """
        message = str(message)

        if self.last_message_ended_with_newline and message.strip() != "":
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_textbox.insert("end", f"[{timestamp}] ")
            self.last_message_ended_with_newline = False
    
        self.log_textbox.insert("end", message)
        if "\n" in message:
            self.last_message_ended_with_newline = True

        self.log_textbox.see("end")
        self.update_idletasks()

    # Select theme for app
    def change_appearance_mode(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    # Scan initialiser
    def start_scan(self, scan_type):
        self.stop_requested = False
        self.log_message(f"Initiating {scan_type.upper()} audit...\n")
        threading.Thread(target=self.run_logic, args=(scan_type,), daemon=True).start()

    # Select scan type and direct it to the scan initializer
    def run_logic(self, scan_type):
        try:
            if scan_type == "storage":
                self.storage_tool.audit_storage()
            elif scan_type == "vm":
                self.vm_tool.audit_vm()
            elif scan_type == "users":
                self.user_tool.audit_users()
            elif scan_type == "keyvault":
                self.keyVault_tool.audit_keyvaults()
            elif scan_type == "vnet":
                self.vnet_tool.audit_vnet()
            self.log_message(f"Completed: {scan_type.capitalize()} scan finished successfully.\n")
        except Exception as e:
            self.log_message(f"Critical error: {str(e)}\n")

    # Scroll through the database findings.
    def open_findings_window(self):
        # Create a new window.
        findings_win = ctk.CTkToplevel(self)
        findings_win.title("Audit History & Security Findings")
        findings_win.geometry("1000x700")
        findings_win.lift()
        findings_win.focus_force()
        findings_win.attributes('-topmost', True)
        findings_win.after(1000, lambda: findings_win.attributes('-topmost', False))

        # Add search/filter feature
        filter_frame = ctk.CTkFrame(findings_win)
        filter_frame.pack(fill="x", padx=10, pady=10)

        # Drop down menu, resource types
        self.type_filter = ctk.CTkOptionMenu(filter_frame, values=["All Types", "Storage", "VM", "User", "KeyVault"])
        self.type_filter.pack(side="left", padx=5)

        # Filter by date
        self.date_filter = ctk.CTkOptionMenu(filter_frame, values=["All Time","Today","Last 7 Days","Last 30 Days"])
        self.date_filter.pack(side="left", padx=5)
        
        # Free search
        self.search_entry = ctk.CTkEntry(filter_frame, placeholder_text="Search resource name or advice...")
        self.search_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        # Search button
        btn_search = ctk.CTkButton(filter_frame, text="Apply Filters", width=100, command=lambda: refresh_data())
        btn_search.pack(side="right", padx=10)
        
        # Scrollable table frame
        results_frame = ctk.CTkScrollableFrame(findings_win)
        results_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Export frame
        export_frame = ctk.CTkFrame(findings_win)
        export_frame.pack(fill="x", padx=10, pady=10)

        # Pass the fetched data to the buttons
        self.current_records = []

        # Refresh feature to clear existing items
        def refresh_data():

            for widget in results_frame.winfo_children():
                widget.destroy()

            self. current_records = self.db.fetch_filtered_findings(
                search_text=self.search_entry.get(),
                resource_type= self.type_filter.get(),
                date_range=self.date_filter.get()
            )

            if not self.current_records:
                ctk.CTkLabel(results_frame, text="No findings found.").pack(pady=20)
                return
            
            type_map = {1:"STORAGE",2:"VM",3:"USER", 4:"KEYVAULT"}
            for rec in self.current_records:
                card = ctk.CTkFrame(results_frame)
                card.pack(fill="x", pady=5, padx=5)

                resource_type = type_map.get(rec[2], str(rec[2]))
                timestamp = rec[4].strftime('%Y-%m-%d %H:%M:%S')
                header_text = f"{timestamp} | {resource_type.upper()} | {rec[1]}"

                lbl = ctk.CTkLabel(card, text=header_text, font=("Consolas", 12, "bold"))
                lbl.pack(side="left", padx=10, pady=10)

                btn_view = ctk.CTkButton(card, text="View Full Analysis", width=120, command=lambda r=rec: self.show_advice_detail(r))
                btn_view.pack(side="right", padx=20)

        refresh_data()

        # Export buttons CSV and PDF
        btn_csv = ctk.CTkButton(export_frame, text="Export CSV", fg_color="gray25", command=lambda: self.export_csv(self.current_records))
        btn_csv.pack(side="left", padx=10, pady=5)

        btn_pdf = ctk.CTkButton(export_frame, text="Export PDF", fg_color="gray25", command=lambda: self.export_pdf(self.current_records))
        btn_pdf.pack(side="left", padx=10, pady=5)

    # Display the AI advice
    def show_advice_detail(self, record):
        detail_win = ctk.CTkToplevel(self)
        detail_win.title(f"Audit Detail: {record[1]}")
        detail_win.geometry("800x600")
        detail_win.attributes('-topmost', True)

        header = ctk.CTkLabel(detail_win, text=f"Resource: {record[1]} ({record[2]})", font=("Consolas", 16, "bold"))
        header.pack(pady=20)

        txt_advice = ctk.CTkTextbox(detail_win, width=780, height=500, font=("Consolas", 22))
        txt_advice.pack(padx=10, pady=10, fill="both", expand=True)
        txt_advice.insert("0.0", record[3])
        txt_advice.configure(state="disabled")

    # Export to CSV
    def export_csv(self, records):
        if not records:
            messagebox.showwarning("Export", "No data available to export.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Export Audit as CSV"
        )
        if file_path:
            try:
                with open(file_path, mode="w", newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["ID","Resource Name","Type ID","AI Advice","Timestamp"])
                    writer.writerows(records)
                messagebox.showinfo("Export success", f"File saved as {file_path}")
            except Exception as e:
                messagebox.showerror(f"Export failed: {e}")

    # Export to PDF
    def export_pdf(self, records):
        if not records:
            messagebox.showwarning("Export", "No data available to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            title="Export Audit as PDF"
        )
        if file_path:
            try:
                c = canvas.Canvas(file_path, pagesize=letter)
                width, height = letter

                c.setFont("Helvetica-Bold", 16)
                c.drawString(50, height - 50, "AzurePilot Security Audit Report")
                c.setFont("Helvetica-Bold", 16)
                c.drawString(50, height - 70, f"Genrated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

                y = height - 100
                for rec in records:
                    if y < 100:
                        c.showPage()
                        y = height - 50

                    c.setFont("Helvetica-Bold", 12)
                    c.drawString(50, y, f"Resource: {rec[1]} (Type: {rec[2]})")
                    y -= 15

                    c.setFont("Helvetica", 10)
                    advice_snippet = (rec[3][:90] + '..') if len(rec[3]) > 90 else rec[3]
                    c.drawString(50, y, f"Advice: {advice_snippet}")
                    y -= 30
                c.save()
                messagebox.showinfo("Export success.", f"PDF saved to {file_path}")
            except Exception as e:
                messagebox.showerror(f"Export failed {e}")

if __name__=="__main__":
    app = AzurePilotApp()
    app.mainloop()