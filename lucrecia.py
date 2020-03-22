
# HONEYPOT MEDIUM-INTERACTION 

# Creator: Kirari

import sys
import time
import socket
import logging
import argparse
import configparser

from os import system
from os.path import isfile
from threading import Thread
from datetime import datetime as dt
from argparse import RawTextHelpFormatter



threads = []

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
		self.passive_mode = False


	def start_new_connection(self):
	
		if self.passive_mode:

			self.socket_, cData = self.dataServer.accept()

		else:

			self.socket_ = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
			self.socket_.connect((self.dataIP,self.dataPort))

		return


	def stop_new_connection(self):

		self.socket_.close()

		if self.passive_mode:

			self.dataServer.close()	

		return


	''' Modo activo por defecto '''

	''' Este modo funciona cuando el cliente solicita el servidor, enviando un comando PORT, a través de un puerto aleatorio, 
	    con un paquete dirigido al puerto 21 (puede ser otro), a fin de transferir un archivo. Una vez establecida la conexión, 
	    el servidor inicia otra.

		El servidor, a través del puerto 20, se pone en contacto inmediatamente con el puerto siguiente del cliente, es decir, 
		imaginemos que el puerto utilizado en la primera conexión, por este, fue el 1500, la utilizada a efectos de la segunda 
		conexión será la 1501 (por ejemplo), canal de datos. ''' 


	def PORT(self,data):

		self.passive_mode = False

		data_client = data.split(',')

		self.dataIP = '.'.join(data_client[:4])
		self.dataPort = (int(data_client[4])*256)+int(data_client[5])

		self.conn.sendall(b"200 PORT command successful. Consider using PASV.\n")

		return


	''' Modo pasivo '''

	''' El cliente abre el canal de coandos a través de un puerto (ej:1500). 
		Envía el comando PASV al servidor dirigido al puerto 21.
		El comando cambia la transmisión al modo pasivo.
		A través del canal de comandos, el servidor envía al cliente el puerto que escuchará el canal de datos, por ejemplo 2345.
		El cliente abre el canal de datos en el puerto 1501 para el puerto 2345 del servidor.
		El servidor confirma la conexión del canal de datos.
		Los canales de comandos y datos están abiertos y listos para su actividad. ''' 


	def PASV(self,host,port):

		self.passive_mode = True

		self.dataServer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.dataServer.bind((host,port))
		self.dataServer.listen(1)

		(ip,port) = self.dataServer.getsockname()

		ip = ','.join(ip.split('.'))

		port = ','.join([str((port // 256)),str(port-((port // 256) * 256))])

		msg = bytes("227 Entering Passive Mode ({},{}).\n".format(ip,port),encoding="utf-8")

		self.conn.sendall(msg)

		return


	def LIST(self):

		self.start_new_connection()
		self.socket_.sendall(b"\r")
		self.stop_new_connection()
		self.conn.sendall(b'150 Here comes the directory listing.\n226 Directory send OK.\n')

		return


	def QUIT(self):

		self.conn.sendall(b'221 Goodbye.\n')
		self.conn.close()

		return 

	def SYST(self):

		self.conn.sendall(b'215 UNIX Type: L8\n')

		return

	def CDUP(self):

		self.conn.sendall(b'250 Directory successfully changed.\n')

		return


	def USER(self):

		self.conn.sendall(b'530 Can\'t change to another user.\n')

		return


	def PWD(self,directory):
		
		pwd = bytes(directory,"utf-8")

		self.conn.sendall(b'257 "'+pwd+b'" is the current directory\n')

		return


	def FTPerror(self):

		self.conn.sendall(b'530 Please login with USER and PASS.\n')

		return

	def LIMIT_HP(self):

		self.conn.sendall(b'550 Permission denied.\n')

		return

	def DISCONNECT(self):

		self.conn.sendall(b"421 Service not available, remote server has closed connection\n")

		return



# Clase Honeypot

class Honeypot(Server):

	def __init__(self,conf):

		Server.__init__(self,conf[0],conf[1])

		self.user = conf[2]
		self.password = conf[3]
		self.currentDirectory = conf[4]

		FORMAT = " [%(levelname)s] (%(asctime)-15s) <%(clientip)s::%(port)s> %(message)s"

		logging.basicConfig(format=FORMAT,filename="Activity.log",level=logging.DEBUG)

		print (" \033[1;39m[\033[1;34m*\033[1;39m] Honeypot Activaded...\n\033[0;39m")


	def run(self):

		cont = 1

		while (True):

			(conn,intruder) = self.server.accept() 	

			# Enviar primer trama

			conn.sendall(b'220 (vsFTPd 3.0.3)\n')
			
			thread = Thread(name="Intruder "+str(cont),target=self.FTP,args=(conn,intruder,))
			threads.append(thread)
			thread.setDaemon(True)
			thread.start()

			cont += 1

		return

	@staticmethod
	def CalcTime():

		datetime = dt.now()

		time_ = "{}:{}:{}".format(datetime.hour,datetime.minute,datetime.second)

		date_ = "{}/{}/{}".format(datetime.day,datetime.month,datetime.year)

		return (time_,date_)


	def FTP(self,connection,client):

		try:

			# Vericar si el atacante se logueo
			self.isLoggedIn = False

			data_info = {"clientip":client[0],'port':client[1]}

			logging.warning("An intruder has accessed the FTP service", extra=data_info)

			print(" [\033[1;33mWARNING\033[0;39m] Someone has accessed the FTP service from {} through port {}.".format(client[0],client[1]))

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

							dt_now = self.CalcTime()

							logging.info("The intruder is logged in.", extra=data_info)

							print(" [\033[1;34m{}\033[0;39m] The intruder is logged in at {} on {}.".format(client[0],dt_now[0],dt_now[1]))
							#print(" [\033[1;32mDATETIME\033[1;39m] {}".format(dt.now()))

							connection.sendall('230 Login successful.\n'.encode())

							self.isLoggedIn = True

							""" 00000000000000000000000000.\n"""
							""" Remote system type is UNIX.\n"""
							""" Using binary mode to transfer files.\n"""


						elif ((user!=self.user) and (password!=self.password)) or \
							 ((user==self.user) and (password!=self.password)) or \
							 ((user!=self.user) and (password==self.password)):

							dt_now = self.CalcTime()

							logging.info("Intruder is trying to log in with credentials: {} -> {}".format(user,password), extra=data_info)

							print(" [\033[1;32mINFO\033[0;39m] Intruder {} is trying to log in with credentials: {} -> {} at {} on {}".format(client[0],user,password,dt_now[0],dt_now[1]))
							#print(" [\033[1;32mDatetime\033[1;39m] {}".format(dt.now()))

							connection.sendall(b'530 Login incorrect.\n')

					else:
						logging.info("The intruder is trying to execute commands.", extra=data_info)

						print(" [\033[1;31m{}\033[0;39m] The intruder is trying to execute commands".format(client[0]))

						handler.FTPerror()	

				else:

					if (activity=="SYST") and (self.isLoggedIn==True):
						logging.info("The intruder is trying to execute commands.", extra=data_info)
						print(" [\033[1;31m{}\033[0;39m] The intruder is executing commands.".format(client[0]))
						handler.SYST()

					elif (activity=="PWD"):
						logging.info("The intruder is using the {} command.".format(activity), extra=data_info)
						print(" [\033[1;31m{}\033[0;39m] The intruder is using the {} command.".format(client[0],activity))
						handler.PWD(self.currentDirectory)

					elif (activity=="CDUP"):
						logging.info("The intruder is using the {} command.".format(activity), extra=data_info)
						print(" [\033[1;31m{}\033[0;39m] The intruder is using the {} command.".format(client[0],activity))
						handler.CDUP()

					elif (activity.startswith("USER")):
						logging.info("The intruder is using the {} command.".format(activity), extra=data_info)
						print(" [\033[1;31m{}\033[0;39m] The intruder is using the {} command.".format(client[0],activity))
						handler.USER()

					elif (activity.startswith("PORT")):
						logging.info("The intruder is using the Active mode to operate.", extra=data_info)
						print(" [\033[1;31m{}\033[0;39m] The intruder is using the Active mode to operate.".format(client[0],activity))
						activity = activity.replace("PORT ","")
						handler.PORT(activity)

					elif (activity.startswith("PASV")):
						logging.info("The intruder is using the Passive mode to operate.", extra=data_info)
						print(" [\033[1;31m{}\033[0;39m] The intruder is using the Passive mode to operate.".format(client[0],activity))
						handler.PASV(client[0],0) # 0 -> indica un puerto aleatorio

					elif (activity=="LIST"):
						logging.info("The intruder is using the {} command.".format(activity), extra=data_info)
						print(" [\033[1;31m{}\033[0;39m] The intruder is using the {} command.".format(client[0],activity))
						handler.LIST()

					else:
						logging.info("Intruder has been denied access to run some commands.", extra=data_info)
						print(" [\033[1;32mINFO\033[0;39m] Access to {} has been denied to run some commands".format(client[0],client[0]))
						handler.LIMIT_HP()

				activity = (connection.recv(2048)).decode(encoding="utf-8")
				activity = activity.strip()


				#print("Petición: ",activity)


			handler.QUIT()
			logging.info("Intruder has disconnected.", extra=data_info)
			print(" [\033[1;34m{}\033[0;39m] Intruder has disconnected.".format(client[0]))


		except BrokenPipeError:

			logging.info("Intruder has fallen", extra=data_info)
			print(" [\033[1;34m{}\033[0;39m] Intruder has fallen.".format(client[0]))


		except KeyboardInterrupt:

			handler.DISCONNECT()

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


def preparate(conf):

	try:

		honeypot = Honeypot(conf)
		honeypot.start()
		honeypot.run()
		#honeypot.stop()

	except KeyboardInterrupt:

		print("\n")

		for _ in threads:

			if (_.isAlive()):

				print (" [*] "+_.name+" disconnected.")
				time.sleep(1)

		honeypot.stop() 

		print ("\n\n \033[1;39m[\033[1;32m+\033[1;39m] Thank you so much for use Lucrecia Honeypot! Bye bye...\n")

	return


def FileConfiguration(file):

	config = configparser.ConfigParser()

	config.read(file)

	sectionDefault = config["DEFAULT"] 

	host = sectionDefault["HOST"]
	port = int(sectionDefault["PORT"])

	sectionFTP = config["FTP"]

	user = sectionFTP["USER"]
	password = sectionFTP["PASSWORD"]
	currentDirectory = sectionFTP["CURRENT_DIRECTORY"]

	return (host,port,user,password,currentDirectory)


def main():

	system("clear")

	print(banner())
	
	parser = argparse.ArgumentParser(add_help=False)

	parser.formatter_class = RawTextHelpFormatter
	parser.description = "\033[1;34m<Honeypot FTP - Medium Interaction>\033[0;39m"
	parser.usage = "lucrecia.py [OPTIONS]"
	parser.epilog = """

\033[1;31mExample:\033[0;39m lucrecia.py -h 192.168.0.18 -p 21
         lucrecia.py -f server.conf 
		
		"""

	sArgs = parser.add_argument_group('\033[1;33mServer Arguments\033[0;39m')
	sArgs.add_argument('-h', '--host', help='IP server', type=str)
	sArgs.add_argument('-p', '--port', help='Port server', type=int, default=21)
	sArgs.add_argument('--directory', help='Set honeypot\'s current directory', type=str, default="/home/test/Server/", metavar="")
	sArgs.add_argument('-U','--user', help="Set user", type=str, default="Testing")
	sArgs.add_argument('-P','--password', help="Set password", type=str, default="toor", metavar="")

	fArgs = parser.add_argument_group('\033[1;33mServer File Arguments\033[0;39m')
	fArgs.add_argument('-f', '--file', help='File configurations')

	args = parser.parse_args()

	if (args.file != None):

		args.host = None
		args.port = None
		args.directory = None
		args.user = None
		args.password = None

		if isfile(args.file):
			
			fconf = FileConfiguration(args.file)

			#print(fconf)

			preparate(fconf)

		else:

			print ("\033[1;39m [\033[1;31mx\033[1;39m] File does not exist.\n")


	elif (args.host!=None) and \
		 (args.port) and \
		 (args.directory) and \
		 (args.user) and \
		 (args.password) and \
		 (args.directory):

			conf = (args.host,args.port,args.user,args.password,args.directory,)

			preparate(conf)		

		#	print ("\033[1;39m [\033[1;31mx\033[1;39m] Some arguments may be wrong.\n")

	else:

		#print(args)

		#print ("\033[1;39m[\033[1;31mx\033[1;39m] Arguments are missing to start the Honeypot\n")

		parser.print_help(sys.stderr)

	
	return


if __name__ == '__main__':

	main()


# ESPERO QUE DISFRUTEN DE ESTA PEQUEÑA TOOL :)