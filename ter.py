import cryptography
import sys
import os
import errno
import time
import random
import string

import base64
import uuid
import stdiomask

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidKey


# Print iterations progress
def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()


def append_folder_padding_files(directory):
	for subdir, _, _ in os.walk(directory):
		filename = subdir + os.sep + "f8fae9b3-8227-4505-aef1-922b701ce0b7-5726e5ec-9681-4884-9f1b-399bddf0a73c.padfile"

		with open(filename, 'wb') as f:
			filesize = random.randint(400, 8000)
			letters = string.ascii_lowercase + string.ascii_uppercase + '0123456789'
			result_str = ''.join(random.choice(letters) for i in range(filesize)).encode()

			result_str +=  b'FILENAME:' + filename.encode()

			f.write(result_str)

def remove_folder_padding_files(directory):
	for subdir, _, filenames in os.walk(directory):
		for filename in filenames:
			if filename == "f8fae9b3-8227-4505-aef1-922b701ce0b7-5726e5ec-9681-4884-9f1b-399bddf0a73c.padfile":
				os.remove(subdir + os.sep + filename)



def get_key(verbose_pass=False):
	print("Please write your password")

	password1 = stdiomask.getpass()
	password1 = password1.encode()

	# Okey for this application, if this application is used for storring multiple users data or something like that
	# A non static salt should be used to avoid rainbow-table vulnerbilities
	salt = b'\xa4\xb4\x11\xde\x05<\xdck\xc1\xfc6R\xaf\x97\xa1j'

	time1 = time.time()

	"""
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt = salt, iterations=5000000, backend=default_backend())
	"""
	kdf = Scrypt(salt = salt, length=32, n = 2**21, r=8, p=1)

	key = base64.urlsafe_b64encode(kdf.derive(password1))
	#key = kdf.derive(password1)

	print("It took ", time.time() - time1, " seconds to generate the key")

	print("Please verify your password")
	password2 = stdiomask.getpass()
	password2 = password2.encode()

	if password2 != password1:
		print("Passwords didn't match")
		exit(-1)

	return key


def encrypt(input_file_names, key):
	fernet = Fernet(key)

	i = 0
	l = len(input_file_names)
	printProgressBar(0, l, prefix='Progress:', suffix='Complete', length = 50)
	for input_file_name in input_file_names:
		i = i + 1
		if i % 4 == 0:
			printProgressBar(i, l, prefix='Progress:', suffix='Complete', length = 50)

		with open(input_file_name, 'rb') as fin:
			data = fin.read() # Read the bytes of the input file
			
			data += b'FILENAME:' + input_file_name.encode()

			encrypted_data = fernet.encrypt(data)

			# Generate random filename
			encrypted_file_name = "Encrypted" + os.sep + str(uuid.uuid4())

			os.makedirs(os.path.dirname(encrypted_file_name), exist_ok=True)
			with open(encrypted_file_name, 'wb') as fout:
				fout.write(encrypted_data) # Write the encrypted bytes to the output file

	printProgressBar(l, l, prefix='Progress:', suffix='Complete', length = 50)


def encryption():
	print("Enter folder containing the files to encrypt")
	folder_to_encrypt = sys.stdin.readline().rstrip()
	if not os.path.exists(folder_to_encrypt):
		print("Entered an non-existing folder")
		exit(-1)

	append_folder_padding_files(folder_to_encrypt)

	# Collect all encrypted file names
	input_file_names = []
	for subdir, _, files in os.walk(folder_to_encrypt):
		for filename in files:
			input_file_names.append(subdir + os.sep + filename)

	key = get_key()

	encrypt(input_file_names, key)

	remove_folder_padding_files(folder_to_encrypt)


def decrypt(input_file_names, encryption_folder_name, key):
	fernet = Fernet(key)

	root_directory_name = None
	i = 0
	l = len(input_file_names)
	printProgressBar(0, l, prefix='Progress:', suffix='Complete', length = 50)
	for input_file_name in input_file_names:
		i = i + 1
		if i % 4 == 0:
			printProgressBar(i, l, prefix='Progress:', suffix='Complete', length = 50)

		with open(encryption_folder_name + os.sep + input_file_name, 'rb') as fin:
			data = fin.read() # Read the bytes of the input file

			try:

				decrypted_data = fernet.decrypt(data)

				decrypted_data, decrypted_file_name = decrypted_data.rsplit(b'FILENAME:', 1)
				
				decrypted_file_name = decrypted_file_name.decode()

				# Ignore padding files
				if "f8fae9b3-8227-4505-aef1-922b701ce0b7-5726e5ec-9681-4884-9f1b-399bddf0a73c.padfile" in decrypted_file_name:
					os.makedirs(os.path.dirname(decrypted_file_name), exist_ok=True)
					continue

				os.makedirs(os.path.dirname(decrypted_file_name), exist_ok=True)
				with open(decrypted_file_name, 'wb') as fout:
					fout.write(decrypted_data)

			except InvalidToken as e:
				print("Invalid key - Unsuccessfully decrypted")
				exit(-1)

	printProgressBar(l, l, prefix='Progress:', suffix='Complete', length = 50)




def decryption(encrypted_folder_name):
	print("Enter folder containing encrypted files")
	folder_to_decrypt = sys.stdin.readline().rstrip()
	if not os.path.exists(folder_to_decrypt):
		print("Enterered an non-existing folder")
		exit(-1)

	input_file_names = []
	for subdir, _, files in os.walk(folder_to_decrypt):
		for filename in files:
			input_file_names.append(filename)

	key = get_key()

	decrypt(input_file_names, encrypted_folder_name, key)



def run():
	n = int(input("Encrypt (1) or decrypt (2)"))
	if (n != 1 and n != 2):
		print("Bad input")
		exit(-1)

	if n == 1:
		encryption()
	elif n == 2:
		decryption("Encrypted")



run()

