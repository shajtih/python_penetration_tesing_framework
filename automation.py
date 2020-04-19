import os
import hashlib
import urllib.request
import re
import bs4

def ACKscan(ip_addr):
	print("Processing...")
	print(os.system("sudo nmap -T4 -sA " + ip_addr ))
	exit()

def XMASscan(ip_addr):
	print("Processing...")
	print(os.system("sudo nmap -T4 -sX " + ip_addr))
	exit()

def FINscan(ip_addr):
	print("Processing...")
	print(os.system("sudo nmap -T4 -sF " + ip_addr))
	exit()

def SYNscan(ip_addr):
	print("Processing...")
	print(os.system("sudo nmap -T4 -sS " + ip_addr))
	exit()


def PortScanning(ip_addr):
	print("""

		 ____   ___  ____ _____   ____   ____    _    _   _
|  _ \ / _ \|  _ \_   _| / ___| / ___|  / \  | \ | |
| |_) | | | | |_) || |   \___ \| |     / _ \ |  \| |
|  __/| |_| |  _ < | |    ___) | |___ / ___ \| |\  |
|_|    \___/|_| \_\|_|   |____/ \____/_/   \_\_| \_|


		Select from the Port Scan Menu:
			1. ACK scan
			2. XMAS scan
			3. FIN scan
			4. SYN scan""")
	userinput = int(input("Enter the option: "))
	if userinput == 1:
		ACKscan(ip_addr)
	elif userinput == 2:
		XMASscan(ip_addr)
	elif userinput == 3:
		FINscan(ip_addr)
	elif userinput == 4:
		SYNscan(ip_addr)
	else:
		print("Provided valid input")

def NetworkSniffer():
	interface=input("Enter the interface: ")
	duration=input("Enter the duraion(s): ")
	path=input("Enter the filename: ")
	print("Processing...")
	tcpdump=os.system("sudo tcpdump -i " + interface + " -a duraion:" + duration + " -w " + path + ".pcap")

def CrackingPassword():
	print("*************************PASSWORD CRACKER*************************")

	#To check if the password
	# found or not
	pass_found = 0
	input_hash = input("Enter the hashed password: ")
	pass_doc = input("\nEnter passwords filename including the path : ")
	try:
	# trying to open the password file
		pass_file = open(pass_doc, 'r')
	except:
		print("Error: ")
		print(pass_doc, "is not found.\nPlease give the path of file correctly.")
		quit()
	# comparing the input_hash with the hashes
	# of the words in password file,
	# and finding password
	for word in pass_file:
	# encoding the word into utf-8 format
		enc_word = word.encode('utf-8')

	#Hasing a word into md5 hash
		hash_word = hashlib.md5(enc_word.strip())

	#digesting the hash into a hexa decimal value
		digest = hash_word.hexdigest()
	
		if digest == input_hash:
		#comparing hashes
			print("Password found.\nThe password is: ", word)
			pass_found = 1
			break
	
	#if password is not found
	if not pass_found:
		print("Passwrd is not found in the", pass_doc, "file")
		print('\n')
	print("*******************************END*******************************")

def WebScrapper():
	target = input("Enter the URL:")
#Extract directories
	print("\nFound URLs:")
	url = urllib.request.urlopen(target).read().decode('utf-8')
	soup = bs4.BeautifulSoup(url, 'html.parser')
	for link in soup.findAll('a', attrs={'href': re.compile("^http[s]://")}):
		print(link.get('href'))

#Extract emaills
	print("\nFound EMails:")
	email_regex = re.compile(r'[\w\d_.-]+@[\w\d_-]+[\w\d_.]+')
	email = re.findall(email_regex, url)
	for i in email:
		print(i)
	 	
#Extract Phone numbers
	print("\nFound Phone Numbers:")
	phone_regex = re.compile(r'(\d{3}[-\.\s]\d{3}[-\.\s]\d{4})')
	phone = re.findall(phone_regex, url)
	for i in phone:
		print(i)
	
def VulScan(ip_addr):
	print("Processing...")
	print((os.system("nmap -Pn -sV -script=vulners.nse " + ip_addr)))

def RunningService(ip_addr):
	print("Processing...")
	#ip_addr = input("Enter the ip address: ")
	service_scan = os.system("sudo nmap -sV -A " + ip_addr)
	print(service_scan)
	exit()




if __name__ == "__main__":

	menu="""
   
 ____                 _             _   _             
|  _ \ ___ _ __   ___| |_ _ __ __ _| |_(_) ___  _ __  
| |_) / _ \ '_ \ / _ \ __| '__/ _` | __| |/ _ \| '_ \ 
|  __/  __/ | | |  __/ |_| | | (_| | |_| | (_) | | | |
|_|   \___|_| |_|\___|\__|_|  \__,_|\__|_|\___/|_| |_|
                                                      
 _____         _   _             
|_   _|__  ___| |_(_)_ __   __ _ 
  | |/ _ \/ __| __| | '_ \ / _` |
  | |  __/\__ \ |_| | | | | (_| |
  |_|\___||___/\__|_|_| |_|\__, |
                           |___/ 
 _____                                            _    
|  ___| __ __ _ _ __ ___   _____      _____  _ __| | __
| |_ | '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
|  _|| | | (_| | | | | | |  __/\ V  V / (_) | |  |   < 
|_|  |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\


	Simple Penetration Testing Framework
		Provide the Option From Menu
		1. IP/Port Scanning
		2. Network Sniffing
		3. Cracking Password 
		4. Collecting Email/URLs/Phone Numbers
		5. Vulnerability Scan
		6. Display Running Services
	"""
	print(menu)

	arg = int(input("Enter the option: "))

try:

	
	if arg == 1:
		ip_addr = input("Enter the ip address: ")
		PortScanning(ip_addr)

	if arg == 2:
		NetworkSniffer()

	if arg == 3:
		CrackingPassword()

	if arg == 4:
		print("Seleted:Collecting Email/URLs/Phone Numbers")
		WebScrapper()

	if arg == 5:
		ip_addr = input("Enter the ip address: ")
		VulScan(ip_addr)

	if arg == 6:
		ip_addr = input("Enter the ip address: ")
		RunningService(ip_addr)

	else:
		print("Invalid Input")

except ValueError:
	pass