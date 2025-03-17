import re
import math
import random
import string

# List of commonly used passwords (for simplicity)
common_passwords = [
    "123456", "password", "123456789", "12345", "qwerty", "abc123", "password1", "letmein", "admin", "P@ssw0rd!", "@1234567#","1234567890",
    "Abc@123#", "abc@123#"
]

def check_password_length(password):
    # Check the length of the password.
    if len(password) < 8:
        return False
    return True

def check_password_complexity(password):
    # Check if the password has a mix of uppercase, lowercase, digits, and special characters.
    if (re.search(r'[a-z]', password) and   # Contains lowercase letter
        re.search(r'[A-Z]', password) and   # Contains uppercase letter
        re.search(r'[0-9]', password) and   # Contains a digit
        re.search(r'[\W_]', password)):     # Contains special character
        return True
    return False

def check_common_password(password):
    # Check if the password is common or easy to guess.
    if password.lower() in common_passwords:
        return True
    return False

def calculate_entropy(password):
    # Calculate the entropy of a password.
    char_space = len(set(password))  # Unique characters
    password_length = len(password)
    if char_space > 1:
        entropy = password_length * math.log2(char_space)
    else:
        entropy = 0
    return entropy

def suggest_password_improvements(password):
    # Suggest improvements for weak passwords.
    suggestions = []
    if not check_password_length(password):
        suggestions.append("Increase the password length to at least 8 characters.")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        suggestions.append("Add at least one lowercase letter.")
    if not re.search(r'[0-9]', password):
        suggestions.append("Include at least one digit.")
    if not re.search(r'[\W_]', password):
        suggestions.append("Include at least one special character.")
    if check_common_password(password):
        suggestions.append("Avoid using common or easily guessable passwords.")
    return suggestions

def generate_strong_password():
    # Generate a random strong password.
    length = 12
    all_characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(all_characters) for _ in range(length))
    return password

def evaluate_password_strength(password):
    # Evaluate the strength of the password based on multiple criteria.
    if not check_password_length(password):
        return "Weak Password! Password must be at least 8 characters long."
    if not check_password_complexity(password):
        return "Medium Password! Password should contain a mix of uppercase, lowercase, digits, and special characters."
    if check_common_password(password):
        return "Weak Password! Password is too common and easy to guess."
    return "Strong: This is a strong password."

# Example usage
if __name__ == "__main__":
    password = input("Enter your password: ")
    strength = evaluate_password_strength(password)
    entropy = calculate_entropy(password)
    print(f"Password entropy: {entropy:.2f} bits")
    print(strength)
    
    if strength.startswith("Weak") or strength.startswith("Medium"):
        print("Suggestions to improve your password:")
        for suggestion in suggest_password_improvements(password):
            print(f"- {suggestion}")
        print("\nHere is a randomly generated strong password you can use:")
        print(generate_strong_password())
