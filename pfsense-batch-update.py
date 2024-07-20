import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re

class EditableTreeview(ttk.Treeview):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.bind("<Double-1>", self.on_double_click)
        self.bind("<Button-3>", self.show_context_menu)
        
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Edit", command=self.on_context_menu_edit)

        self._current_row = None
        self._current_column = None

    def on_double_click(self, event=None):
        if event:
            region = self.identify_region(event.x, event.y)
            if region == "cell":
                self._current_column = self.identify_column(event.x)
                self._current_row = self.identify_row(event.y)
                self.edit_cell(self._current_row, self._current_column, event)

    def edit_cell(self, row, column, event=None):
        item = self.item(row)
        col_idx = int(column[1:]) - 1
        value = item["values"][col_idx]

        entry = tk.Entry(self)
        entry.insert(0, value)
        entry.place(x=event.x_root - self.winfo_rootx(), y=event.y_root - self.winfo_rooty(), anchor="w")
        entry.focus()

        def save_edit(event):
            new_value = entry.get()
            values = list(item["values"])
            values[col_idx] = new_value
            self.item(row, values=values)
            entry.destroy()

        entry.bind("<Return>", save_edit)
        entry.bind("<FocusOut>", lambda e: entry.destroy())

    def show_context_menu(self, event):
        self._current_column = self.identify_column(event.x)
        self._current_row = self.identify_row(event.y)
        self.context_menu.post(event.x_root, event.y_root)

    def on_context_menu_edit(self):
        if self._current_row and self._current_column:
            self.edit_cell(self._current_row, self._current_column)

def parse_config(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    dhcp_entries = []
    dns_entries = []

    dhcp_pattern = re.compile(r'<staticmap>(.*?)</staticmap>', re.DOTALL)
    for match in dhcp_pattern.findall(content):
        entry = {
            'mac': re.search(r'<mac>(.*?)</mac>', match).group(1),
            'ipaddr': re.search(r'<ipaddr>(.*?)</ipaddr>', match).group(1),
            'hostname': re.search(r'<hostname>(.*?)</hostname>', match).group(1),
            'descr': re.search(r'<descr>(.*?)</descr>', match).group(1)
        }
        dhcp_entries.append(entry)

    dns_pattern = re.compile(r'<hosts>(.*?)</hosts>', re.DOTALL)
    for match in dns_pattern.findall(content):
        entry = {
            'host': re.search(r'<host>(.*?)</host>', match).group(1),
            'domain': re.search(r'<domain>(.*?)</domain>', match).group(1),
            'ip': re.search(r'<ip>(.*?)</ip>', match).group(1),
            'descr': re.search(r'<descr>(.*?)</descr>', match).group(1),
            'aliases': '; '.join([
                f"{alias.group(1)}.{alias.group(2)}" for alias in re.finditer(r'<item><host>(.*?)</host><domain>(.*?)</domain></item>', match)
            ])
        }
        dns_entries.append(entry)

    return content, dhcp_entries, dns_entries

def load_file():
    global current_file_path, original_content
    file_path = filedialog.askopenfilename(filetypes=[("XML files", "*.xml")])
    if file_path:
        current_file_path = file_path
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)
        original_content, dhcp_entries, dns_entries = parse_config(file_path)
        populate_treeview(dhcp_treeview, dhcp_entries)
        populate_treeview(dns_treeview, dns_entries)

def populate_treeview(treeview, entries):
    for entry in treeview.get_children():
        treeview.delete(entry)
    
    if entries:
        columns = list(entries[0].keys())
        treeview.config(columns=columns)
        for col in columns:
            treeview.heading(col, text=col)
            treeview.column(col, width=150)
        
        for entry in entries:
            values = [entry[col] for col in columns]
            treeview.insert('', 'end', values=values)

def save_file():
    global current_file_path, original_content
    if not current_file_path:
        messagebox.showerror("Error", "No file loaded")
        return
    
    dhcp_entries = get_treeview_entries(dhcp_treeview)
    dns_entries = get_treeview_entries(dns_treeview)

    new_content = original_content

    # Update DHCP entries
    for entry in dhcp_entries:
        new_content = re.sub(
            r'<staticmap>(?:(?!</staticmap>).)*<mac>{0}</mac>.*?<ipaddr>.*?</ipaddr>.*?<hostname>.*?</hostname>.*?<descr>.*?</descr>.*?</staticmap>'.format(re.escape(entry['mac'])),
            '<staticmap><mac>{mac}</mac><ipaddr>{ipaddr}</ipaddr><hostname>{hostname}</hostname><descr>{descr}</descr></staticmap>'.format(**entry),
            new_content,
            flags=re.DOTALL
        )

    # Update DNS entries
    for entry in dns_entries:
        aliases_str = ''.join([f'<item><host>{alias.split(".")[0]}</host><domain>{alias.split(".")[1]}</domain></item>' for alias in entry['aliases'].split('; ')])
        new_content = re.sub(
            r'<hosts>(?:(?!</hosts>).)*<host>{0}</host>.*?<domain>.*?</domain>.*?<ip>.*?</ip>.*?<descr>.*?</descr>.*?<aliases>.*?</aliases>.*?</hosts>'.format(re.escape(entry['host'])),
            '<hosts><host>{host}</host><domain>{domain}</domain><ip>{ip}</ip><descr>{descr}</descr><aliases>{aliases}</aliases></hosts>'.format(host=entry['host'], domain=entry['domain'], ip=entry['ip'], descr=entry['descr'], aliases=aliases_str),
            new_content,
            flags=re.DOTALL
        )

    with open(current_file_path, 'w', encoding='utf-8') as file:
        file.write(new_content)
    
    messagebox.showinfo("Success", "File saved successfully")

def get_treeview_entries(treeview):
    entries = []
    for row in treeview.get_children():
        entry = {}
        for col in treeview["columns"]:
            entry[col] = treeview.item(row, 'values')[treeview["columns"].index(col)]
        entries.append(entry)
    return entries

def load_inventory():
    file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if file_path:
        with open(file_path, 'r') as f:
            lines = f.readlines()
            for line in lines[1:]:  # Skip header
                fields = line.strip().split(',')
                if len(fields) == 4:  # DHCP entry
                    dhcp_treeview.insert('', 'end', values=fields)
                elif len(fields) == 5:  # DNS entry
                    dns_treeview.insert('', 'end', values=fields)

# Initializing global variables
current_file_path = None
original_content = None

root = tk.Tk()
root.title("PFSense Config Viewer")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

file_frame = ttk.Frame(frame, padding="5")
file_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E))

file_label = ttk.Label(file_frame, text="Config File:")
file_label.grid(row=0, column=0, sticky=tk.W, padx=5)

file_entry = ttk.Entry(file_frame, width=60)
file_entry.grid(row=0, column=1, padx=5, pady=5)

browse_button = ttk.Button(file_frame, text="...", command=load_file)
browse_button.grid(row=0, column=2, padx=5, pady=5)

save_button = ttk.Button(frame, text="Save Changes", command=save_file)
save_button.grid(row=0, column=3, padx=5, pady=5)

inventory_button = ttk.Button(frame, text="Load Inventory", command=load_inventory)
inventory_button.grid(row=0, column=4, padx=5, pady=5)

dhcp_label = ttk.Label(frame, text="DHCP Entries")
dhcp_label.grid(row=1, column=0, pady=5, sticky=tk.W)

dhcp_treeview = EditableTreeview(frame, show='headings', height=10)
dhcp_treeview.grid(row=2, column=0, columnspan=5, pady=5, sticky=(tk.W, tk.E))

dns_label = ttk.Label(frame, text="DNS Entries")
dns_label.grid(row=3, column=0, pady=5, sticky=tk.W)

dns_treeview = EditableTreeview(frame, show='headings', height=10)
dns_treeview.grid(row=4, column=0, columnspan=5, pady=5, sticky=(tk.W, tk.E))

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
frame.columnconfigure(0, weight=1)

root.mainloop()
