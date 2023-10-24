import select
import socket
import sys
import signal
import argparse
import ssl
import hashlib
import os
import json

from utils import *

SERVER_HOST = 'localhost'

class ChatServer(object):
    """ An example chat server using select """

    def __init__(self, port, backlog=5):
        self.clients = 0
        self.clientmap = {}
        self.outputs = []  # list output sockets
        self.user_db = {}
        self.logged_in_users = set()

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2, ssl.CERT_NONE)
        self.context.load_cert_chain(certfile="cert.pem", keyfile="cert.pem")
        self.context.load_verify_locations('cert.pem')
        self.context.set_ciphers('AES128-SHA')

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((SERVER_HOST, port))
        self.server.listen(backlog)                
        self.server = self.context.wrap_socket(self.server, server_side=True)

        # Load user database from file
        try:
            with open('user_db.json', 'r') as f:
                self.user_db = json.load(f)
        except FileNotFoundError:
            self.user_db = {}
        except json.JSONDecodeError:
            self.user_db = {} # If the file is empty or not properly formatted, initialize an empty user database

        # Catch keyboard interrupts
        signal.signal(signal.SIGINT, self.sighandler)

        print(f'Server listening to port: {port} ...')

    def sighandler(self, signum, frame):
        """ Clean up client outputs"""
        print('Shutting down server...')

        # Close existing client sockets
        for output in self.outputs:
            output.close()

        self.server.close()

    def get_client_name(self, client):
        """ Return the name of the client """
        info = self.clientmap[client]
        host, name = info[0][0], info[1]
        return '@'.join((name, host))
    
    # Hash Password
    def hash_password(self, password):
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt + key

    # Verify Password
    def verify_password(self, stored_password, provided_password):
        stored_password_bytes = bytes.fromhex(stored_password) # Convert hex string back to bytes
        salt = stored_password_bytes[:32]
        stored_key = stored_password_bytes[32:]
        key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return stored_key == key

    # Register Function
    def register(self, username, password):
        if username in self.user_db:
            return False # User already exists
        else:
            self.user_db[username] = self.hash_password(password).hex() # Convert bytes to hex string for JSON serialization
            with open('user_db.json', 'w') as f: # Write user database to file
                json.dump(self.user_db, f)
            return True # Registration successful

    # Login Function
    def login(self, username, password):
        if username not in self.user_db:
            return False # User doesn't exist
        elif username in self.logged_in_users:
            return False # User is already logged in
        elif not self.verify_password(bytes.fromhex(self.user_db[username]), password):
            return False # Incorrect password
        else:
            self.logged_in_users.add(username) # Add user to logged in users
            return True

    def run(self):
        inputs = [self.server]
        self.outputs = []
        running = True
        while running:
            try:
                readable, writeable, exceptional = select.select(
                    inputs, self.outputs, [])
            except select.error as e:
                break

            for sock in readable:
                sys.stdout.flush()
                if sock == self.server:
                    # handle the server socket
                    client, address = self.server.accept()
                    send(client, 'Do you want to (1) register or (2) login?')
                    response = receive(client)
                    if response == '1':
                        username = receive(client)
                        password = receive(client)
                        success = self.register(username, password)
                        if not success:
                            send(client, 'Registration failed')
                            continue
                        else:
                            send(client, f'CLIENT: {str(address[0])}')
                            self.clientmap[client] = (address, username) # Update client's name in clientmap
                            
                    elif response == '2':
                        username = receive(client)
                        password = receive(client)
                        success = self.login(username, password)
                        if not success:
                            send(client, 'Login failed')
                            continue
                        else:
                            send(client, f'CLIENT: {str(address[0])}') 
                            self.clientmap[client] = (address, username) # Update client's name in clientmap

                    print(f'Chat server: got connection {client.fileno()} from {address}')
                    # Read the login name
                    cname = receive(client).split('NAME: ')[1]

                    # Compute client name and send back
                    self.clients += 1
                    inputs.append(client)

                    self.clientmap[client] = (address, cname)
                    # Send joining information to other clients
                    msg = f'\n(Connected: New client ({self.clients}) from {self.get_client_name(client)})'
                    for output in self.outputs:
                        send(output, msg)
                    self.outputs.append(client)
                else:
                    # handle all other sockets
                    try:
                        data = receive(sock)
                        if data:
                            # Send as new client's message...
                            msg = f'\n#[{self.get_client_name(sock)}]>> {data}'

                            # Send data to all except ourself
                            for output in self.outputs:
                                if output != sock:
                                    send(output, msg)
                        else:
                            print(f'Chat server: {sock.fileno()} hung up')
                            self.clients -= 1
                            sock.close()
                            inputs.remove(sock)
                            self.outputs.remove(sock)

                            # Sending client leaving information to others
                            msg = f'\n(Now hung up: Client from {self.get_client_name(sock)})'

                            for output in self.outputs:
                                send(output, msg)
                    except socket.error as e:
                        # Remove
                        inputs.remove(sock)
                        self.outputs.remove(sock)
                        
        self.server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Socket Server Example with Select')
    parser.add_argument('--name', action="store", dest="name", required=True)
    parser.add_argument('--port', action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args()
    port = given_args.port
    name = given_args.name

    server = ChatServer(port)
    server.run()