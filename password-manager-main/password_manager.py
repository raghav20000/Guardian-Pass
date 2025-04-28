import os
import getpass
from datetime import datetime

class PasswordManager:
    def __init__(self):
        self.accounts = {}  # Dictionary to store account: (encrypted_password, category, notes, last_updated)
        self.master_pin = None
        self.filename = "passwords.txt"
        self.backup_folder = "password_backups"
        
    def _encrypt(self, password, shift=3):
        """Improved encryption using character shifting with variable shift"""
        encrypted = []
        for i, char in enumerate(password):
            current_shift = shift + i  # Varying shift for better security
            encrypted_char = chr((ord(char) + current_shift) % 256)
            encrypted.append(encrypted_char)
        return ''.join(encrypted)
    
    def _decrypt(self, encrypted, shift=3):
        """Decrypts the shifted characters with variable shift"""
        decrypted = []
        for i, char in enumerate(encrypted):
            current_shift = shift + i
            decrypted_char = chr((ord(char) - current_shift) % 256)
            decrypted.append(decrypted_char)
        return ''.join(decrypted)
    
    def _normalize_pin(self, pin):
        """Ensure PIN is 4-6 digits"""
        pin_str = str(pin)
        if len(pin_str) < 4 or len(pin_str) > 6:
            raise ValueError("PIN must be 4-6 digits")
        return int(pin)
    
    def set_pin(self, pin):
        """Set the master PIN with validation"""
        try:
            self.master_pin = self._normalize_pin(pin)
        except ValueError as e:
            print(f"Error: {e}")
            return False
        return True
    
    def check_pin(self, entered_pin):
        """Verify if entered PIN matches master PIN"""
        try:
            return self._normalize_pin(entered_pin) == self.master_pin
        except ValueError:
            return False
    
    def _create_backup(self):
        """Create a backup of the password file"""
        if not os.path.exists(self.backup_folder):
            os.makedirs(self.backup_folder)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(self.backup_folder, f"passwords_backup_{timestamp}.txt")
        
        try:
            with open(self.filename, 'r') as source, open(backup_file, 'w') as target:
                target.write(source.read())
        except Exception as e:
            print(f"Backup failed: {e}")
    
    def load_accounts(self):
        """Load accounts from file if it exists with error handling"""
        try:
            self._create_backup()  # Create backup before loading
            
            if not os.path.exists(self.filename):
                print("No password file found. Starting fresh.")
                return
            
            with open(self.filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Format: account|encrypted_password|category|notes|last_updated
                    parts = line.split('|')
                    if len(parts) >= 2:
                        account = parts[0]
                        encrypted = parts[1]
                        category = parts[2] if len(parts) > 2 else "General"
                        notes = parts[3] if len(parts) > 3 else ""
                        last_updated = parts[4] if len(parts) > 4 else str(datetime.now())
                        
                        self.accounts[account] = {
                            'password': encrypted,
                            'category': category,
                            'notes': notes,
                            'updated': last_updated
                        }
                        
        except Exception as e:
            print(f"Error loading accounts: {e}")
    
    def save_accounts(self):
        """Save all accounts to file with error handling"""
        try:
            self._create_backup()
            
            with open(self.filename, 'w') as f:
                for account, data in self.accounts.items():
                    line = f"{account}|{data['password']}|{data['category']}|{data['notes']}|{data['updated']}"
                    f.write(line + "\n")
            print("Passwords saved successfully.")
            return True
        except Exception as e:
            print(f"Error saving accounts: {e}")
            return False
    
    def add_password(self, account, password, category="General", notes=""):
        """Add new account password with additional metadata"""
        if account in self.accounts:
            print(f"Account {account} already exists. Use 'update' to change it.")
            return False
        
        encrypted = self._encrypt(password)
        self.accounts[account] = {
            'password': encrypted,
            'category': category,
            'notes': notes,
            'updated': str(datetime.now())
        }
        print(f"Password added for {account}!")
        return True
    
    def update_password(self, account, new_password, new_category=None, new_notes=None):
        """Update existing account password and metadata"""
        if account not in self.accounts:
            print(f"Account {account} doesn't exist.")
            return False
        
        encrypted = self._encrypt(new_password)
        self.accounts[account]['password'] = encrypted
        self.accounts[account]['updated'] = str(datetime.now())
        
        if new_category is not None:
            self.accounts[account]['category'] = new_category
        if new_notes is not None:
            self.accounts[account]['notes'] = new_notes
        
        print(f"Password updated for {account}!")
        return True
    
    def get_password(self, account, pin):
        """Retrieve password if PIN is correct"""
        if not self.check_pin(pin):
            print("Wrong PIN! Access denied.")
            return None
        
        if account in self.accounts:
            decrypted = self._decrypt(self.accounts[account]['password'])
            return decrypted
        else:
            print(f"No account named {account} found.")
            return None
    
    def get_account_details(self, account, pin):
        """Get all details for an account"""
        if not self.check_pin(pin):
            print("Wrong PIN! Access denied.")
            return None
        
        if account in self.accounts:
            details = self.accounts[account].copy()
            details['password'] = self._decrypt(details['password'])
            return details
        else:
            print(f"No account named {account} found.")
            return None
    
    def delete_account(self, account, pin):
        """Delete an account if PIN is correct"""
        if not self.check_pin(pin):
            print("Wrong PIN! Can't delete.")
            return False
        
        if account in self.accounts:
            del self.accounts[account]
            print(f"Account {account} deleted.")
            return True
        else:
            print(f"Account {account} doesn't exist.")
            return False
    
    def show_accounts(self, category_filter=None):
        """List all stored accounts with optional category filter"""
        if not self.accounts:
            print("No accounts stored yet.")
            return
        
        print("\nYour saved accounts:")
        print("-" * 50)
        print(f"{'No.':<4} {'Account':<20} {'Category':<15} {'Last Updated':<20}")
        print("-" * 50)
        
        filtered_accounts = self.accounts.items()
        if category_filter:
            filtered_accounts = [(a, d) for a, d in self.accounts.items() 
                               if d['category'].lower() == category_filter.lower()]
        
        for i, (account, data) in enumerate(filtered_accounts, 1):
            updated = data['updated'].split('.')[0]  # Remove microseconds
            print(f"{i:<4} {account:<20} {data['category']:<15} {updated:<20}")
    
    def search_accounts(self, search_term):
        """Search accounts by name or notes"""
        results = []
        search_term = search_term.lower()
        
        for account, data in self.accounts.items():
            if (search_term in account.lower() or 
                search_term in data['notes'].lower()):
                results.append((account, data))
        
        if not results:
            print("No matching accounts found.")
            return
        
        print("\nSearch results:")
        print("-" * 50)
        print(f"{'No.':<4} {'Account':<20} {'Category':<15}")
        print("-" * 50)
        
        for i, (account, data) in enumerate(results, 1):
            print(f"{i:<4} {account:<20} {data['category']:<15}")
        
        return results
    
    def change_master_pin(self, old_pin, new_pin):
        """Change the master PIN with verification"""
        if not self.check_pin(old_pin):
            print("Incorrect current PIN.")
            return False
        
        try:
            normalized_new = self._normalize_pin(new_pin)
        except ValueError as e:
            print(f"Invalid new PIN: {e}")
            return False
        
        self.master_pin = normalized_new
        print("Master PIN changed successfully.")
        return True
    
    def export_to_file(self, filename, pin):
        """Export passwords to a file (encrypted)"""
        if not self.check_pin(pin):
            print("Wrong PIN! Access denied.")
            return False
        
        try:
            with open(filename, 'w') as f:
                for account, data in self.accounts.items():
                    line = f"{account}|{data['password']}|{data['category']}|{data['notes']}|{data['updated']}\n"
                    f.write(line)
            print(f"Passwords exported to {filename} successfully.")
            return True
        except Exception as e:
            print(f"Error exporting passwords: {e}")
            return False
    
    def import_from_file(self, filename, pin):
        """Import passwords from a file"""
        if not self.check_pin(pin):
            print("Wrong PIN! Access denied.")
            return False
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split('|')
                    if len(parts) >= 2:
                        account = parts[0]
                        encrypted = parts[1]
                        category = parts[2] if len(parts) > 2 else "General"
                        notes = parts[3] if len(parts) > 3 else ""
                        last_updated = parts[4] if len(parts) > 4 else str(datetime.now())
                        
                        self.accounts[account] = {
                            'password': encrypted,
                            'category': category,
                            'notes': notes,
                            'updated': last_updated
                        }
            
            print(f"Passwords imported from {filename} successfully.")
            return True
        except Exception as e:
            print(f"Error importing passwords: {e}")
            return False

def get_valid_pin(prompt="Enter PIN (4-6 digits): "):
    """Helper to get a valid PIN"""
    while True:
        pin = getpass.getpass(prompt).strip()
        if pin.isdigit() and 4 <= len(pin) <= 6:
            return int(pin)
        print("Invalid PIN - must be 4-6 digits.")

def get_non_empty_input(prompt, hidden=False):
    """Get non-empty input from user"""
    while True:
        if hidden:
            value = getpass.getpass(prompt).strip()
        else:
            value = input(prompt).strip()
        if value:
            return value
        print("This field cannot be empty.")

def display_menu():
    """Display the main menu"""
    print("\n=== Password Manager Menu ===")
    print("1. Add new password")
    print("2. View password")
    print("3. View account details")
    print("4. Update password")
    print("5. List accounts")
    print("6. Search accounts")
    print("7. Delete account")
    print("8. Change master PIN")
    print("9. Export passwords")
    print("10. Import passwords")
    print("11. Save & Exit")
    print("12. Exit without saving")

def main():
    print("\n=== Enhanced Password Manager ===")
    manager = PasswordManager()
    manager.load_accounts()
    
    # Set up PIN if first run
    if manager.master_pin is None:
        print("\nSet up your master PIN (4-6 digits)")
        while True:
            pin = get_valid_pin()
            if manager.set_pin(pin):
                break
    
    while True:
        display_menu()
        
        try:
            choice = input("Your choice (1-12): ").strip()
            if not choice.isdigit():
                raise ValueError
            choice = int(choice)
            if choice < 1 or choice > 12:
                raise ValueError
        except ValueError:
            print("Please enter a number between 1 and 12")
            continue
        
        if choice == 1:  # Add new password
            account = get_non_empty_input("Account name: ")
            password = get_non_empty_input("Password: ", hidden=True)
            category = input("Category (press Enter for 'General'): ").strip() or "General"
            notes = input("Notes (optional): ").strip()
            manager.add_password(account, password, category, notes)
        
        elif choice == 2:  # View password
            account = get_non_empty_input("Account name: ")
            pin = get_valid_pin()
            password = manager.get_password(account, pin)
            if password:
                print(f"\nPassword for {account}: {password}")
        
        elif choice == 3:  # View account details
            account = get_non_empty_input("Account name: ")
            pin = get_valid_pin()
            details = manager.get_account_details(account, pin)
            if details:
                print("\nAccount Details:")
                print("-" * 40)
                print(f"Account: {account}")
                print(f"Category: {details['category']}")
                print(f"Password: {details['password']}")
                print(f"Last Updated: {details['updated'].split('.')[0]}")
                print(f"Notes: {details['notes']}")
        
        elif choice == 4:  # Update password
            account = get_non_empty_input("Account name: ")
            if account not in manager.accounts:
                print(f"Account {account} doesn't exist.")
                continue
            
            pin = get_valid_pin()
            current_password = manager.get_password(account, pin)
            if not current_password:
                continue
            
            print(f"\nCurrent password for {account}: {current_password}")
            new_password = get_non_empty_input("New password: ", hidden=True)
            new_category = input(f"New category (current: {manager.accounts[account]['category']}, press Enter to keep): ").strip()
            new_notes = input(f"New notes (current: {manager.accounts[account]['notes']}, press Enter to keep): ").strip()
            
            manager.update_password(
                account, 
                new_password,
                new_category if new_category else None,
                new_notes if new_notes else None
            )
        
        elif choice == 5:  # List accounts
            category_filter = input("Enter category to filter by (or press Enter for all): ").strip()
            manager.show_accounts(category_filter if category_filter else None)
        
        elif choice == 6:  # Search accounts
            search_term = get_non_empty_input("Enter search term: ")
            manager.search_accounts(search_term)
        
        elif choice == 7:  # Delete account
            account = get_non_empty_input("Account to delete: ")
            pin = get_valid_pin("Enter PIN to confirm deletion: ")
            manager.delete_account(account, pin)
        
        elif choice == 8:  # Change master PIN
            old_pin = get_valid_pin("Enter current PIN: ")
            new_pin = get_valid_pin("Enter new PIN (4-6 digits): ")
            if manager.change_master_pin(old_pin, new_pin):
                print("Master PIN changed successfully.")
        
        elif choice == 9:  # Export passwords
            filename = get_non_empty_input("Enter export filename: ")
            pin = get_valid_pin()
            manager.export_to_file(filename, pin)
        
        elif choice == 10:  # Import passwords
            filename = get_non_empty_input("Enter import filename: ")
            pin = get_valid_pin()
            manager.import_from_file(filename, pin)
        
        elif choice == 11:  # Save & Exit
            if manager.save_accounts():
                print("Goodbye!")
                break
        
        elif choice == 12:  # Exit without saving
            print("Exiting without saving changes.")
            break

if __name__ == "__main__":
    main()
