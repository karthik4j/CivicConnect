import os
from twilio.rest import Client
from dotenv import load_dotenv
from pathlib import Path

# Find the venv folder relative to this file
base_dir = Path(__file__).resolve().parents[0]  # adjust if needed
#print(base_dir)
venv_env = base_dir / ".env" / ".env"

# Load .env from inside venv
load_dotenv(venv_env)

def format_indian_number(num_str: str) -> str:

    # Keep only digits
    digits = "".join(filter(str.isdigit, num_str))

    # Case 1: Already includes country code (91)
    if digits.startswith("91") and len(digits) == 12:
        return "+" + digits

    # Case 2: Only 10-digit local Indian number
    if len(digits) == 10:
        return "+91" + digits

    # If none match, error out
    raise ValueError(f"Invalid Indian phone number: {num_str}")


def send_message(number: str, text: str):
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    from_number = os.getenv("TWILIO_PHONE_NUMBER")

    client = Client(account_sid, auth_token)

    twilio_msg = client.messages.create(
        body=text,
        from_=from_number,
        to=format_indian_number(number),
    )

    print("Sent:", twilio_msg.body)

#print("Checking ENV SID: ",account_sid," token: ",auth_token," fromnum ",from_number)
#print("Sent:", message.body)
send_message("x","This is a test. If you see this. There is hope.")
#print(format_indian_number("x"))