import os
import json
import base64
import sqlite3
import platform
import operator
from shutil import copyfile
from collections import OrderedDict
from Crypto.Cipher import AES
import matplotlib.pyplot as plt

# For Linux keyring support
try:
    import secretstorage
    LINUX_SUPPORT = True
except ImportError:
    LINUX_SUPPORT = False

# For Windows support
try:
    import win32crypt
    WINDOWS_SUPPORT = True
except ImportError:
    WINDOWS_SUPPORT = False

class BrowserConfig:
    def __init__(self, name, windows_path, linux_path, mac_path):
        self.name = name
        self.windows_path = windows_path
        self.linux_path = linux_path
        self.mac_path = mac_path

    def get_path(self):
        system = platform.system().lower()
        if system == "windows":
            return os.path.join(os.environ["LOCALAPPDATA"], self.windows_path)
        elif system == "linux":
            return os.path.expanduser(self.linux_path)
        elif system == "darwin":
            return os.path.expanduser(self.mac_path)
        raise OSError(f"Unsupported operating system: {system}")

# Define browser configurations
BROWSERS = {
    "1": BrowserConfig(
        "Google Chrome",
        r"Google\Chrome\User Data",
        "~/.config/google-chrome",
        "~/Library/Application Support/Google/Chrome"
    ),
    "2": BrowserConfig(
        "Microsoft Edge",
        r"Microsoft\Edge\User Data",
        "~/.config/microsoft-edge",
        "~/Library/Application Support/Microsoft Edge"
    ),
    "3": BrowserConfig(
        "Brave Browser",
        r"BraveSoftware\Brave-Browser\User Data",
        "~/.config/BraveSoftware/Brave-Browser",
        "~/Library/Application Support/BraveSoftware/Brave-Browser"
    ),
    "4": BrowserConfig(
        "Vivaldi",
        r"Vivaldi\User Data",
        "~/.config/vivaldi",
        "~/Library/Application Support/Vivaldi"
    ),
    "5": BrowserConfig(
        "Opera",
        r"Opera Software\Opera Stable",
        "~/.config/opera",
        "~/Library/Application Support/com.operasoftware.Opera"
    ),
    "6": BrowserConfig(
        "Chromium",
        r"Chromium\User Data",
        "~/.config/chromium",
        "~/Library/Application Support/Chromium"
    )
}

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if platform.system().lower() == "windows" else 'clear')

def display_main_menu():
    """Display the main menu and return the selected option."""
    clear_screen()
    print("Browser Analysis Tools:")
    print("=" * 50)
    print("1. Password Extraction")
    print("2. History Analysis")
    print("3. Exit")
    print("=" * 50)
    
    while True:
        choice = input("\nSelect an option (1-3): ")
        if choice in ['1', '2', '3']:
            return choice
        print("Invalid selection. Please try again.")

def display_browser_menu():
    """Display the browser selection menu and return the selected browser config."""
    clear_screen()
    print("Available Browsers:")
    print("=" * 50)
    for key, browser in BROWSERS.items():
        print(f"{key}. {browser.name}")
    print("=" * 50)
    
    while True:
        choice = input("\nSelect a browser (or 'q' to quit): ").lower()
        if choice == 'q':
            return None
        if choice in BROWSERS:
            return BROWSERS[choice]
        print("Invalid selection. Please try again.")

def parse_url(url):
    """Parse the domain from a URL."""
    try:
        parsed_url_components = url.split('//')[1].split('/')[0]
        domain = parsed_url_components.replace('www.', '')
        return domain
    except IndexError:
        return None

def analyze_history(browser_config):
    """Analyze browser history."""
    try:
        # Get browser path and history file
        browser_path = get_browser_path(browser_config)
        history_path = os.path.join(browser_path, "Default", "History")
        
        if not os.path.exists(history_path):
            print(f"[Error] History database not found at: {history_path}")
            return
        
        # Create a copy of the history file
        temp_history = f"{browser_config.name} - History - Copy"
        copyfile(history_path, temp_history)
        
        try:
            # Connect to the database
            conn = sqlite3.connect(temp_history)
            cursor = conn.cursor()
            cursor.execute('SELECT urls.url, urls.visit_count FROM urls, visits WHERE urls.id = visits.url;')
            
            results = cursor.fetchall()
            if not results:
                print("No browsing history found.")
                return
            
            # Process results
            sites_count = {}
            for url, count in results:
                domain = parse_url(url)
                if domain:
                    sites_count[domain] = sites_count.get(domain, 0) + count
            
            # Sort results
            sites_count_sorted = OrderedDict(sorted(sites_count.items(), 
                                                  key=operator.itemgetter(1), 
                                                  reverse=True))
            
            # Save to file
            output_file = f"{browser_config.name.lower().replace(' ', '_')}_history.txt"
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"History Analysis for {browser_config.name}:\n\n")
                for site, count in sites_count_sorted.items():
                    f.write(f"{site} -> {count}\n")
            
            # Display options
            while True:
                print("\nDisplay options:")
                print("1. Print to console")
                print("2. Show graph")
                print("3. Return to main menu")
                
                choice = input("\nSelect an option (1-3): ")
                
                if choice == '1':
                    print(f"\nTop visited sites for {browser_config.name}:")
                    for site, count in sites_count_sorted.items():
                        print(f"{site} -> {count}")
                elif choice == '2':
                    # Take top 20 sites for better visualization
                    top_sites = dict(list(sites_count_sorted.items())[:20])
                    plt.figure(figsize=(15, 8))
                    plt.bar(range(len(top_sites)), top_sites.values(), align='edge')
                    plt.xticks(range(len(top_sites)), top_sites.keys(), rotation=45, ha='right')
                    plt.title(f"Top 20 Most Visited Sites - {browser_config.name}")
                    plt.xlabel("Domains")
                    plt.ylabel("Visit Count")
                    plt.tight_layout()
                    plt.show()
                elif choice == '3':
                    break
                
            print(f"\nHistory has been saved to: {output_file}")
            
        finally:
            conn.close()
            try:
                os.remove(temp_history)
            except Exception:
                pass
    
    except Exception as e:
        print(f"[Error] Failed to analyze history: {e}")

def get_browser_path(browser_config):
    """Get the path to browser data."""
    return browser_config.get_path()

def get_master_key(browser_path, return_encrypted=False):
    """Retrieve the AES master key based on the operating system."""
    system = platform.system().lower()
    
    if system == "windows" and WINDOWS_SUPPORT:
        local_state_path = os.path.join(browser_path, "Local State")
        try:
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
            
            if return_encrypted:
                return {
                    "encrypted_key_base64": encrypted_key_b64,
                    "encrypted_key_bytes": encrypted_key,
                    "encrypted_key_no_prefix": encrypted_key[5:],
                    "decrypted_key": win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
                }
            
            return win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
        except FileNotFoundError:
            raise Exception(f"Local State file not found at: {local_state_path}")
    
    elif system == "linux" and LINUX_SUPPORT:
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        key = None
        for item in collection.get_all_items():
            if item.get_label() == "Chrome Safe Storage":
                key = item.get_secret()
                if return_encrypted:
                    return {
                        "keyring_key": key,
                        "decrypted_key": key
                    }
                return key
        raise Exception("Chrome Safe Storage key not found in keyring")
    
    elif system == "darwin":
        raise NotImplementedError("macOS support not yet implemented")
    
    else:
        raise OSError(f"Unsupported operating system or missing requirements: {system}")

def clean_decrypted_data(data):
    """Clean decrypted data by removing non-printable characters and truncating at null byte."""
    try:
        # First, truncate at the first null byte if present
        if '\x00' in data:
            data = data.split('\x00')[0]
        
        # Remove any remaining non-printable characters
        cleaned = ''.join(char for char in data if ord(char) >= 32 and ord(char) <= 126)
        return cleaned.strip()
    except Exception:
        return data

def decrypt_password(encrypted_password, master_key, debug=False):
    """Decrypt AES-encrypted password."""
    try:
        # Ensure we're working with bytes
        if not isinstance(encrypted_password, bytes):
            return "[Invalid encrypted password format]"

        # Check for minimum length
        if len(encrypted_password) < 31:  # 3 bytes prefix + 12 bytes IV + 16 bytes minimum ciphertext
            return "[Password data too short]"

        # Extract the initialization vector (12 bytes) and ciphertext
        iv = encrypted_password[3:15]
        ciphertext = encrypted_password[15:]

        # Create cipher object and decrypt the data
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(ciphertext[:-16])  # Remove auth tag

        try:
            # Attempt to decode as UTF-8 first
            decoded = decrypted_pass.decode('utf-8')
        except UnicodeDecodeError:
            try:
                # Fall back to latin-1 if UTF-8 fails
                decoded = decrypted_pass.decode('latin-1')
            except Exception:
                return "[Decoding Failed]"

        # Clean the decoded password
        cleaned_pass = clean_decrypted_data(decoded)
        
        if debug:
            print(f"Original length: {len(encrypted_password)}")
            print(f"Decrypted length: {len(decrypted_pass)}")
            print(f"Cleaned length: {len(cleaned_pass)}")

        return cleaned_pass if cleaned_pass else "[Empty Password]"

    except Exception as e:
        if debug:
            print(f"[Error] Failed to decrypt password: {e}")
        return "[Decryption Failed]"

def display_master_key(browser_config):
    """Display the master key information in different formats."""
    try:
        browser_path = get_browser_path(browser_config)
        key_info = get_master_key(browser_path, return_encrypted=True)
        
        clear_screen()
        print(f"\nMaster Key Information for {browser_config.name}:")
        print("=" * 50)
        
        if platform.system().lower() == "windows":
            print("Base64 Encoded Key:")
            print(f"{key_info['encrypted_key_base64']}\n")
            
            print("Encrypted Key (bytes):")
            print(f"{key_info['encrypted_key_bytes'].hex()}\n")
            
            print("Encrypted Key (no DPAPI prefix):")
            print(f"{key_info['encrypted_key_no_prefix'].hex()}\n")
            
            print("Decrypted Key (bytes):")
            print(f"{key_info['decrypted_key'].hex()}\n")
            
            print("Decrypted Key (base64):")
            print(f"{base64.b64encode(key_info['decrypted_key']).decode()}\n")
        
        elif platform.system().lower() == "linux":
            print("Keyring Key (bytes):")
            print(f"{key_info['keyring_key'].hex()}\n")
            
            print("Keyring Key (base64):")
            print(f"{base64.b64encode(key_info['keyring_key']).decode()}\n")
        
        print("=" * 50)
        return key_info
    
    except Exception as e:
        print(f"[Error] Failed to retrieve master key information: {e}")
        return None

def extract_passwords(browser_config, debug=False):
    """Extract and decrypt saved passwords from the browser's Login Data database."""
    browser_path = get_browser_path(browser_config)
    login_db_path = os.path.join(browser_path, "Default", "Login Data")
    
    if not os.path.exists(login_db_path):
        print(f"[Error] Login Data database not found at: {login_db_path}")
        return
    
    # Copy the database to avoid locking issues
    temp_db_path = f"{browser_config.name} - Login Data - Copy"
    copyfile(login_db_path, temp_db_path)
    
    try:
        # Connect to the copied database
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        
        # Get the master key
        master_key = get_master_key(browser_path)
        
        # Open a file to log the output
        output_file = f"{browser_config.name.lower().replace(' ', '_')}_passwords.txt"
        with open(output_file, "w", encoding="utf-8") as log_file:
            print(f"\nPasswords for {browser_config.name}:")
            log_file.write(f"Passwords for {browser_config.name}:\n")
            
            for i, (url, username, encrypted_password) in enumerate(cursor.fetchall(), start=1):
                if not username or not encrypted_password:
                    continue
                
                decrypted_password = decrypt_password(encrypted_password, master_key, debug=debug)
                
                # Format output strings
                url_line = f"[{i}] {url}"
                username_line = f"Username: {username}"
                password_line = f"Password: {decrypted_password}"
                
                # Write to console
                print(url_line)
                print(f"\t{username_line}")
                print(f"\t{password_line}\n")
                
                # Write to log file
                log_file.write(f"{url_line}\n")
                log_file.write(f"\t{username_line}\n")
                log_file.write(f"\t{password_line}\n\n")
            
            print(f"\nPasswords have been saved to: {output_file}")
    
    except Exception as e:
        print(f"[Error] Failed to extract passwords: {e}")
    
    finally:
        # Clean up
        conn.close()
        try:
            os.remove(temp_db_path)
        except Exception:
            pass

def main():
    # Print system information
    print(f"Operating System: {platform.system()} {platform.release()}")
    
    # Check for required dependencies
    if platform.system().lower() == "windows" and not WINDOWS_SUPPORT:
        print("[Warning] win32crypt module not found. Install with: pip install pywin32")
    elif platform.system().lower() == "linux" and not LINUX_SUPPORT:
        print("[Warning] secretstorage module not found. Install with: pip install secretstorage")
    
    while True:
        # Display main menu
        choice = display_main_menu()
        
        if choice == '3':  # Exit
            break
        
        # Get browser selection
        browser_config = display_browser_menu()
        if not browser_config:
            continue
        
        try:
            if choice == '1':  # Password Extraction
                key_info = display_master_key(browser_config)
                if key_info:
                    response = input("\nDo you want to extract passwords? (y/n): ").lower()
                    if response == 'y':
                        extract_passwords(browser_config, debug=False)
            
            elif choice == '2':  # History Analysis
                analyze_history(browser_config)
            
            input("\nPress Enter to continue...")
        
        except Exception as e:
            print(f"\n[Error] An error occurred with {browser_config.name}: {e}")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()