import re
import bcrypt  # Install this library using `pip install bcrypt`

def check_password(password):
    # List to collect feedback
    feedback = []
    
    # Length check
    if len(password) < 12:
        feedback.append("Password should be at least 12 characters long.")
    
    # Uppercase check
    if not re.search("[A-Z]", password):
        feedback.append("Password should have at least one uppercase letter.")
    
    # Lowercase check
    if not re.search("[a-z]", password):
        feedback.append("Password should have at least one lowercase letter.")
    
    # Digit check
    if not re.search("[0-9]", password):
        feedback.append("Password should have at least one number.")
    
    # Special character check
    if not re.search(r"[@$!%*?&#]", password):
        feedback.append("Password should have at least one special character (e.g., @, $, %, &).")
    
    # Evaluate feedback
    if feedback:
        print("Password is weak. Suggestions:")
        for issue in feedback:
            print(f"- {issue}")
        return False
    else:
        print("Password is strong!")
        return True

def hash_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# Main program
password = input("Enter your password: ")
if check_password(password):
    hashed_password = hash_password(password)
    print("Your password has been hashed securely:")
    print(hashed_password.decode())  # Decode to show the hashed string
