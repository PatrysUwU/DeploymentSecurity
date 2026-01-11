import hashlib
import os
import pickle
import subprocess

# --- 1. Hardcoded password (B105) ---
DB_PASSWORD = "super_secret_password"


# --- 2. Użycie eval() (B307) ---
def calculate(expression):
    return eval(expression)


# --- 3. Deserializacja niezaufanych danych pickle (B301) ---
def load_data(filename):
    with open(filename, "rb") as f:
        data = pickle.load(f)
    return data


# --- 4. Uruchamianie polecenia z inputu użytkownika (B602 / B607) ---
def run_command():
    cmd = input("Podaj polecenie: ")
    subprocess.call(cmd, shell=True)


# --- 5. Słaby algorytm hashujący (MD5) (B303) ---
def hash_password(password: str):
    return hashlib.md5(password.encode()).hexdigest()


# --- 6. Użycie assert do walidacji bezpieczeństwa (B101) ---
def withdraw(balance, amount):
    assert amount <= balance, "Za mało środków!"
    return balance - amount


if __name__ == "__main__":
    print("Wynik obliczeń:", calculate("2 + 2"))
    print("Hash:", hash_password("admin"))
    run_command()
