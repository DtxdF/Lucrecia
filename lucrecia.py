
# HONEYPOT MEDIUM-INTERACTION 

# Creator: Kirari

import sys
import time
import socket
import argparse
import configparser

from os import system
from os.path import isfile
from threading import Thread
from datetime import datetime as dt
from argparse import RawTextHelpFormatter

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

		print (" \033[1;39m[\033[1;34m*\033[1;39m] Honeypot Activaded...\n")

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

	def LIMIT_HP(self):

		self.conn.sendall(b'550 Permission denied.\n')

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

						print("[\033[1;32mIntruso detectado\033[1;39m] He's logged in from {} through port {}.".format(client[0],client[1]))
						print("[\033[1;32mDatetime\033[1;39m] {}\n".format(dt.now()))

						connection.sendall('230 Login successful.\n'.encode())

						self.isLoggedIn = True

						""" 00000000000000000000000000.\n"""
						""" Remote system type is UNIX.\n"""
						""" Using binary mode to transfer files.\n"""


					elif ((user!=self.user) and (password!=self.password)) or \
						 ((user==self.user) and (password!=self.password)) or \
						 ((user!=self.user) and (password==self.password)):


						print("[\033[1;32mIntruso detectado\033[1;39m] Intruder is trying to log in with credentials: {} -> {}.".format(user,password))
						print("[\033[1;32mDatetime\033[1;39m] {}\n".format(dt.now()))

						connection.sendall(b'530 Login incorrect.\n')

				else:
					print("[\033[1;32m{}-Movement\033[1;39m] The intruder is trying to execute commands".format(client[0]))
					handler.FTPerror()	

			else:

				if (activity=="SYST") and (self.isLoggedIn==True):
					print("[\033[1;32m{}-Movement\033[1;39m] TThe intruder is executing commands.".format(client[0]))
					handler.SYST()

				elif (activity=="PWD"):
					print("[\033[1;32m{}-Movement\033[1;39m] The intruder is using the {} command.".format(client[0],activity))
					handler.PWD()

				else:
					print("[\033[1;32m{}-Movement\033[1;39m] Access to {} has been denied to run some commands".format(client[0],client[0]))
					handler.LIMIT_HP()

			activity = (connection.recv(2048)).decode(encoding="utf-8")
			activity = activity.strip()


			#print("Petición: ",activity)


		handler.QUIT()
		print("[\033[1;32m{}-Movement\033[1;39m] Intruder has disconnected.".format(client[0]))

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
	msg += "                 ░                        ░  \n"
	msg += "                        \033[1;39mHONEYPOT\n\n"
	msg += "                   Created by Kirari\n\033[0;39m"

	return msg


def preparate(host,port):

	try:

		honeypot = Honeypot(host,port)
		honeypot.start()
		honeypot.run()
		honeypot.stop()

	except KeyboardInterrupt:

		honeypot.stop() 

	return


def FileConfiguration(file):

	config = configparser.ConfigParser()

	config.read(file)

	sectionDefault = config["DEFAULT"] 

	host = sectionDefault["HOST"]
	port = int(sectionDefault["PORT"])

	return host,port


def main():

	system("clear")

	print(banner())
	
	parser = argparse.ArgumentParser()

	parser.formatter_class = RawTextHelpFormatter
	parser.description = "\033[1;34m<Honeypot FTP - Medium Interaction>\033[0;39m"
	parser.usage = "lucrecia.py [OPTIONS]"
	parser.epilog = """

\033[1;31mExample:\033[0;39m lucrecia.py -h 192.168.0.18 -p 21
         lucrecia.py -f server.conf 
		
		"""

	sArgs = parser.add_argument_group('\033[1;33mServer Arguments\033[0;39m')
	sArgs.add_argument('-H', '--host', help='Host server', type=str)
	sArgs.add_argument('-P', '--port', help='Port server', type=int, default=21)

	fArgs = parser.add_argument_group('\033[1;33mServer File Arguments\033[0;39m')
	fArgs.add_argument('-f', '--file', help='File configurations')

	args = parser.parse_args()

	if (args.file != None):

		if isfile(args.file):
			
			fconf = FileConfiguration(args.file)

			#print(fconf)

			preparate(fconf[0],fconf[1])

	elif (args.host!=None):

		if (args.host!=None) and (args.port):

			preparate(args.host,args.port)


	else:

		print ("\033[1;39m[\033[1;31mx\033[1;39m] Arguments are missing to start the Honeypot\n")

		parser.print_help(sys.stderr)

	
	return


if __name__ == '__main__':

	main()