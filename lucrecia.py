
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


# Clase manipuladora FTP 

class HandlingFTP(object):

	def __init__(self,conn):

		self.conn = conn

	def QUIT(self):

		self.conn.sendall(b'221 Goodbye.\n')
		self.conn.close()

		return 

	def SYST(self):

		self.conn.sendall(b'215 UNIX Type: L8\n')

		return

	def PWD(self):
		
		pwd = b"/"

		self.conn.sendall(b'257 "'+pwd+b'" is the current directory\n')

		return


	def FTPerror(self):

		self.conn.sendall(b'530 Please login with USER and PASS.\n')

		return

# Clase Honeypot

class Honeypot(Server):

	def __init__(self,host,port):

		Server.__init__(self,host,port)

		self.user = "dinamic"
		self.password = "toor"


	def run(self):

		while (True):

			(conn,intruder) = self.server.accept() 	

			# Enviar primer trama

			conn.sendall(b'220 (vsFTPd 3.0.3)\n')
			
			thread = Thread(target=self.FTP,args=(conn,intruder,))
			thread.start()

		return


	def FTP(self,connection,client):

		# Vericar si el atacante se logueo
		self.isLoggedIn = False

		# Datos enviados por atacante
		activity = (connection.recv(2048)).decode(encoding="utf-8")
		
		# Manipulador de comandos FTP
		handler = HandlingFTP(connection)


		while (activity!="QUIT"):

			if (self.isLoggedIn==False):

				if (activity.startswith("USER")):

					user = (activity.strip()).split()[1]

					#print(self.user)

					connection.sendall(b"331 Please specify the password.\n")

				elif (activity.startswith("PASS")):

					password = (activity.strip()).split()[1]

					#print(self.password)

					if (user==self.user) and (password==self.password):

						#print("[\033[1;32m{}:{}\033[0;39m] Intruso ha iniciado sesión.".format(client[0],client[1]))

						connection.sendall('230 Login successful.\n'.encode())

						self.isLoggedIn = True

						""" 00000000000000000000000000.\n"""
						""" Remote system type is UNIX.\n"""
						""" Using binary mode to transfer files.\n"""

						#conn.sendall(b'Remote system type is UNIX.\n')

					elif ((user!=self.user) and (password!=self.password)) or \
						 ((user==self.user) and (password!=self.password)) or \
						 ((user!=self.user) and (password==self.password)):


						#print("[\033[1;32m{}:{}\033[0;39m] Intruso está intentando iniciar sesión con las credenciales: {} -> {}.".format(client[0],client[1],user,password))

						connection.sendall(b'530 Login incorrect.\n')

				else:
					handler.FTPerror()	

			else:

				if (activity=="SYST") and (self.isLoggedIn==True):
					handler.SYST()

				elif (activity=="PWD"):
					handler.PWD()

			activity = (connection.recv(2048)).decode(encoding="utf-8")
			activity = activity.strip()


			print("Petición: ",activity)
			

		handler.QUIT()

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