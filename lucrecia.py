
# HONEYPOT MEDIUM-INTERACTION 

# Creator: Kirari

import os
import sys
import time
import socket

from threading import Thread

# Clase servidor

class Server(object):

	def __init__(self,host,port):

		self.host = host
		self.port = port

	def create_socket(self):

		try:
			self.server = socket.socket()
			self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		except socket.error as s:
			print("Error: ",s)
			sys.exit(0)

		return

	def start(self):

		self.create_socket()
		self.server.bind((self.host,self.port))
		self.server.listen(10)

		return 

	def stop(self):

		self.server.close()

		return


# Clase Honeypot

class Honeypot(Server):

	def __init__(self,host,port):

		Server.__init__(self,host,port)

		self.user = "dinamic"
		self.password = "toor"
		self.isLogged = False
		self.data_complete = False

		self.attackers = []

	def run(self):

		while (True):

			(conn,intruder) = self.server.accept() 	

			# Enviar primer trama

			conn.sendall(b'220 (vsFTPd 3.0.3)\n')
			
			thread = Thread(target=self.FTP,args=(conn,))
			thread.start()

		return


	def FTP(self,client):

		while (True):

			activity = (client.recv(2048)).decode(encoding="utf-8")

			if (activity.startswith("USER")):

				user = (activity.strip()).split()[1]

				#print(self.user)

				client.sendall(b"331 Please specify the password.\n")

			elif (activity.startswith("PASS")):

				password = (activity.strip()).split()[1]

				#print(self.password)


				if (self.isLogged==False) and ((user==self.user) and (password==self.password)):

					self.isLogged = True
					self.data_complete = True
					client.sendall('230 Login successful.\n'.encode())

					""" 00000000000000000000000000.\n"""
					""" Remote system type is UNIX.\n"""
					""" Using binary mode to transfer files.\n"""

					#conn.sendall(b'Remote system type is UNIX.\n')

				elif (self.isLogged==False) or (((user!=self.user) and (password!=self.password)) or \
					 ((user==self.user) and (password!=self.password)) or \
					 ((user!=self.user) and (password==self.password))):

					self.data_complete = True
					client.sendall(b'530 Login incorrect.\nLogin failed.\n')

			print(activity)

			if (activity.strip()=="QUIT"):
				client.sendall(b'221 Goodbye.\n')
				client.close()
				break

			elif (self.isLogged!=False) and (activity.strip()=="SYST"):
				client.sendall(b'215 UNIX Type: L8\n')

		return



def banner():

	msg = "\n\n\033[0;31m"
	msg += " ██▓     █    ██  ▄████▄   ██▀███  ▓█████  ▄████▄   ██▓ ▄▄▄  \n"
	msg += "▓██▒     ██  ▓██▒▒██▀ ▀█  ▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▓██▒▒████▄    \n"
	msg += "▒██░    ▓██  ▒██░▒▓█    ▄ ▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██▒▒██  ▀█▄  \n"
	msg += "▒██░    ▓▓█  ░██░▒▓▓▄ ▄██▒▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒░██░░██▄▄▄▄██ \n"
	msg += "░██████▒▒▒█████▓ ▒ ▓███▀ ░░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░██░ ▓█   ▓██▒\n"
	msg += "░ ▒░▓  ░░▒▓▒ ▒ ▒ ░ ░▒ ▒  ░░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░▓   ▒▒   ▓▒█░\n"
	msg += "░ ░ ▒  ░░░▒░ ░ ░   ░  ▒     ░▒ ░ ▒░ ░ ░  ░  ░  ▒    ▒ ░  ▒   ▒▒ ░\n"
	msg += "  ░ ░    ░░░ ░ ░ ░          ░░   ░    ░   ░         ▒ ░  ░   ▒   \n"
	msg += "    ░  ░   ░     ░ ░         ░        ░  ░░ ░       ░        ░  ░\n"
	msg += "                 ░                        ░  \n\033[0;39m"
	msg += "                        HONEYPOT\n\n"
	msg += "                   Created by Kirari\n"

	return msg


if __name__ == '__main__':

	os.system("clear")

	print(banner())
	
	try:
		h = Honeypot("192.168.0.18",5000)
		h.start()
		h.run()
		h.stop()
	except KeyboardInterrupt:
		h.stop()