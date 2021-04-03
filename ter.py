import cryptography
import sys
import os
import errno

import base64
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.fernet import Fernet, InvalidToken


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




def get_key(verbose_pass=False):
	print("Please write your password")

	password = sys.stdin.readline().rstrip()
	password = password.encode()

	# Okey for this application, if this application is used for storring multiple users data or something like that
	# A non static salt should be used to avoid rainbow-table vulnerbilities
	salt = b'\xa4\xb4\x11\xde\x05<\xdck\xc1\xfc6R\xaf\x97\xa1j'

	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt = salt,
		iterations=100000,
		backend=default_backend()
	)

	key = base64.urlsafe_b64encode(kdf.derive(password))

	return key


def encrypt(input_file_names, key):
	fernet = Fernet(key)

	i = 0
	l = len(input_file_names)
	printProgressBar(0, l, prefix='Progress:', suffix='Complete', length = 50)
	for input_file_name in input_file_names:
		i = i + 1
		if i % 20 == 0:
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

	# Collect all encrypted file names
	input_file_names = []
	for subdir, _, files in os.walk(folder_to_encrypt):
		for filename in files:
			input_file_names.append(subdir + os.sep + filename)

	key = get_key()

	encrypt(input_file_names, key)


def decrypt(input_file_names, encryption_folder_name, key):
	fernet = Fernet(key)

	i = 0
	l = len(input_file_names)
	printProgressBar(0, l, prefix='Progress:', suffix='Complete', length = 50)
	for input_file_name in input_file_names:
		i = i + 1
		if i % 20 == 0:
			printProgressBar(i, l, prefix='Progress:', suffix='Complete', length = 50)

		with open(encryption_folder_name + os.sep + input_file_name, 'rb') as fin:
			data = fin.read() # Read the bytes of the input file

			try:

				decrypted_data = fernet.decrypt(data)

				decrypted_data, decrypted_file_name = decrypted_data.rsplit(b'FILENAME:', 1)

				os.makedirs(os.path.dirname(decrypted_file_name.decode()), exist_ok=True)
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


