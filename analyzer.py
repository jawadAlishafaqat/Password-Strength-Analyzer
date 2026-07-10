
# ==========================================
# Password Strength Analyzer
# analyzer.py (Version 2)
# Part 1
# ==========================================

# Import libraries
import math
import string
from collections import Counter

# Import configuration
from config import *


# Load dictionary words
def load_dictionary(file_path="dictionary.txt"):

    words = set()

    try:

        with open(file_path, "r", encoding="utf-8") as file:

            for line in file:

                word = line.strip().lower()

                if word:
                    words.add(word)

    except FileNotFoundError:

        print("Warning: dictionary.txt not found.")

    return words


# Load dictionary once
DICTIONARY_WORDS = load_dictionary()


# Check password length
def check_password_length(password):

    return len(password)


# Check character types
def check_character_types(password):

    return {

        "Uppercase": any(c.isupper() for c in password),

        "Lowercase": any(c.islower() for c in password),

        "Digit": any(c.isdigit() for c in password),

        "Symbol": any(not c.isalnum() for c in password)

    }


# Check dictionary words
def check_dictionary_words(password):

    password = password.lower()

    found = []

    for word in DICTIONARY_WORDS:

        if len(word) >= 3 and word in password:
            found.append(word)

    return sorted(found)


# Check keyboard patterns
def check_keyboard_patterns(password):

    password = password.lower()

    patterns = [

        "qwerty",
        "asdf",
        "zxcv",
        "12345",
        "123456",
        "987654",
        "password",
        "admin"

    ]

    found = []

    for pattern in patterns:

        if pattern in password:
            found.append(pattern)

    return found


# Check sequential numbers
def check_sequential_numbers(password):

    found = []

    for i in range(len(password) - 2):

        part = password[i:i + 3]

        if part.isdigit():

            if ord(part[1]) == ord(part[0]) + 1 and ord(part[2]) == ord(part[1]) + 1:
                found.append(part)

            elif ord(part[1]) == ord(part[0]) - 1 and ord(part[2]) == ord(part[1]) - 1:
                found.append(part)

    return sorted(list(set(found)))


# Check repeated characters
def check_repeated_characters(password):

    repeated = []

    counts = Counter(password)

    for char, count in counts.items():

        if count >= 3:
            repeated.append((char, count))

    return repeated


# Check alternating letter-number pattern
def check_alternating_pattern(password):

    if len(password) < 6:
        return False

    matches = 0

    for i in range(len(password) - 1):

        if password[i].isalpha() and password[i + 1].isdigit():
            matches += 1

        elif password[i].isdigit() and password[i + 1].isalpha():
            matches += 1

    return matches >= len(password) // 2


# Get password statistics
def get_password_statistics(password):

    return {

        "Length": len(password),

        "Uppercase Letters": sum(c.isupper() for c in password),

        "Lowercase Letters": sum(c.islower() for c in password),

        "Digits": sum(c.isdigit() for c in password),

        "Special Characters": sum(not c.isalnum() for c in password),

        "Unique Characters": len(set(password))

    } 

    # Calculate password entropy
def calculate_entropy(password):

    character_pool = 0

    if any(c.islower() for c in password):
        character_pool += 26

    if any(c.isupper() for c in password):
        character_pool += 26

    if any(c.isdigit() for c in password):
        character_pool += 10

    if any(c in string.punctuation for c in password):
        character_pool += len(string.punctuation)

    if character_pool == 0:
        return 0, 0

    entropy = round(len(password) * math.log2(character_pool), 2)

    return entropy, character_pool


# Calculate effective entropy
def calculate_effective_entropy(password):

    entropy, pool = calculate_entropy(password)

    effective_entropy = entropy

    # Length penalty
    if len(password) < 8:
        effective_entropy -= 35

    elif len(password) < 12:
        effective_entropy -= 20

    elif len(password) < 15:
        effective_entropy -= 10

    # Dictionary penalty
    words = check_dictionary_words(password)

    if words:
        effective_entropy -= min(len(words) * 20, 40)

    # Keyboard pattern penalty
    patterns = check_keyboard_patterns(password)

    if patterns:
        effective_entropy -= 15

    # Sequential numbers penalty
    sequences = check_sequential_numbers(password)

    if sequences:
        effective_entropy -= 15

    # Repeated characters penalty
    repeated = check_repeated_characters(password)

    if repeated:
        effective_entropy -= 10

    # Alternating pattern penalty
    if check_alternating_pattern(password):
        effective_entropy -= 15

    effective_entropy = max(0, round(effective_entropy, 2))

    return effective_entropy


# Calculate password score
def calculate_password_score(password):

    score = 0

    weaknesses = []

    # Length
    length = len(password)

    if length >= 15:
        score += 30

    elif length >= 12:
        score += 20

    elif length >= 8:
        score += 10
        weaknesses.append(
            "Password length can be improved (Recommended: 15+ characters)"
        )

    else:
        weaknesses.append(
            "Password is too short (Minimum recommended: 8 characters)"
        )

    # Character types
    char_types = check_character_types(password)

    if char_types["Uppercase"]:
        score += 10
    else:
        weaknesses.append("Missing uppercase letter")

    if char_types["Lowercase"]:
        score += 10
    else:
        weaknesses.append("Missing lowercase letter")

    if char_types["Digit"]:
        score += 10
    else:
        weaknesses.append("Missing digit")

    if char_types["Symbol"]:
        score += 10
    else:
        weaknesses.append("Missing special character")

    # Dictionary words
    words = check_dictionary_words(password)

    if words:
        score -= 20
        weaknesses.append(
            "Contains dictionary word(s): " + ", ".join(words)
        )

    # Keyboard patterns
    patterns = check_keyboard_patterns(password)

    if patterns:
        score -= 15
        weaknesses.append(
            "Contains keyboard pattern(s): " + ", ".join(patterns)
        )

    # Sequential numbers
    sequences = check_sequential_numbers(password)

    if sequences:
        score -= 15
        weaknesses.append(
            "Contains sequential number(s): " + ", ".join(sequences)
        )

    # Repeated characters
    repeated = check_repeated_characters(password)

    if repeated:
        score -= 10
        weaknesses.append("Contains repeated characters")

    # Alternating pattern
    if check_alternating_pattern(password):
        score -= 10
        weaknesses.append(
            "Contains predictable letter-number pattern"
        )

    score = max(0, min(score, 100))

    return score, weaknesses


# Get password strength
def get_strength_level(score):

    if score <= 20:
        return "Very Weak"

    elif score <= 40:
        return "Weak"

    elif score <= 60:
        return "Moderate"

    elif score <= 80:
        return "Strong"

    return "Excellent"
    # Generate recommendations
def generate_recommendations(password):

    recommendations = []

    if len(password) < 15:
        recommendations.append(
            "Increase password length to at least 15 characters."
        )

    if check_dictionary_words(password):
        recommendations.append(
            "Avoid using common dictionary words."
        )

    if check_keyboard_patterns(password):
        recommendations.append(
            "Avoid keyboard patterns such as qwerty or asdf."
        )

    if check_sequential_numbers(password):
        recommendations.append(
            "Avoid sequential numbers such as 123 or 456."
        )

    if check_repeated_characters(password):
        recommendations.append(
            "Avoid repeating the same character multiple times."
        )

    if check_alternating_pattern(password):
        recommendations.append(
            "Avoid predictable letter-number combinations."
        )

    char_types = check_character_types(password)

    if not all(char_types.values()):
        recommendations.append(
            "Use uppercase, lowercase, digits and special characters."
        )

    if not recommendations:
        recommendations.append(
            "Excellent password. No improvements needed."
        )

    return recommendations


# Identify attack type
def identify_attack(password):

    if check_dictionary_words(password):
        return "Dictionary Attack"

    elif check_keyboard_patterns(password):
        return "Keyboard Pattern Attack"

    elif check_sequential_numbers(password):
        return "Sequential Attack"

    elif check_alternating_pattern(password):
        return "Pattern Attack"

    elif check_repeated_characters(password):
        return "Pattern Attack"

    else:
        return "Brute Force Attack"


# Estimate crack time
def estimate_realistic_crack_time(password):

    effective_entropy = calculate_effective_entropy(password)

    if effective_entropy < 20:
        return "Instantly"

    elif effective_entropy < 40:
        return "Few Seconds"

    elif effective_entropy < 60:
        return "Few Minutes"

    elif effective_entropy < 80:
        return "Several Hours"

    else:
        return "Several Days"


# Analyze password
def analyze_password(password):

    score, weaknesses = calculate_password_score(password)

    strength = get_strength_level(score)

    entropy, pool = calculate_entropy(password)

    effective_entropy = calculate_effective_entropy(password)

    attack_type = identify_attack(password)

    crack_time = estimate_realistic_crack_time(password)

    statistics = get_password_statistics(password)

    recommendations = generate_recommendations(password)

    report = {

        "Password": password,

        "Score": score,

        "Strength": strength,

        "Entropy": entropy,

        "Effective Entropy": effective_entropy,

        "Character Pool": pool,

        "Attack Type": attack_type,

        "Estimated Crack Time": crack_time,

        "Statistics": statistics,

        "Weaknesses": weaknesses,

        "Recommendations": recommendations

    }

    return report


# Test analyzer
if __name__ == "__main__":

    password = input("Enter Password: ")

    report = analyze_password(password)

    print("\n" + "=" * 55)
    print("PASSWORD ANALYSIS REPORT")
    print("=" * 55)

    print(f"Password             : {report['Password']}")
    print(f"Score                : {report['Score']}/100")
    print(f"Strength             : {report['Strength']}")
    print(f"Entropy              : {report['Entropy']} bits")
    print(f"Effective Entropy    : {report['Effective Entropy']} bits")
    print(f"Attack Type          : {report['Attack Type']}")
    print(f"Estimated Crack Time : {report['Estimated Crack Time']}")

    print("\nPassword Statistics")
    print("-" * 55)

    for key, value in report["Statistics"].items():
        print(f"{key:<22}: {value}")

    print("\nWeaknesses")
    print("-" * 55)

    if report["Weaknesses"]:
        for item in report["Weaknesses"]:
            print(f"• {item}")
    else:
        print("• None")

    print("\nRecommendations")
    print("-" * 55)

    for item in report["Recommendations"]:
        print(f"• {item}")

    print("=" * 55)
