#!/usr/bin/python3

import os
import sys
from getpass import getpass
import tempfile
import subprocess
import gnupg
import argparse
import string
import secrets

gpg = gnupg.GPG()

# config
CIPHER = "AES256"
DEFAULT_PWLEN = 13
CLIP_ON_GEN = True


WORKINGDIR = "~/.pa"
PWGEN_SYMBOLS = ".,;:-_#+*~?\\=<>[]{}()/&%$!|^"
EDITOR = os.environ.get('EDITOR', 'vim')

class CryptoError(Exception):
	pass

def error(msg):
	print(msg, file=sys.stderr)
	sys.exit(1)

def workingdir():
	return os.path.expanduser(WORKINGDIR)

def dbdir():
	return os.path.join(workingdir(), 'db')

def entryfile(entry):
	return os.path.join(dbdir(), entry)

def db_initialized():
	return os.path.isfile(entryfile("../dbinfo.gpg"))

def encrypt(entry, passphrase, value):
	if not value.endswith("\n"):
		value += "\n"
	crypt = gpg.encrypt(value.encode('UTF-8'), None, passphrase=passphrase, symmetric=CIPHER, armor=False)
	if not crypt.ok:
		raise CryptoError("Encryption failed!")
	open(entryfile(entry), 'wb').write(crypt.data)
	os.chmod(entryfile(entry), 0o600)

def decrypt(entry, passphrase):
	ct = open(entryfile(entry), 'rb').read()
	crypt = gpg.decrypt(ct, passphrase=passphrase)
	if not crypt.ok:
		raise CryptoError("Decryption failed!")
	return crypt.data.decode("UTF-8")

def check_passphrase(passphrase, raise_exception=False):
	try:
		decrypt("../dbinfo.gpg", passphrase)
		return True
	except CryptoError:
		if raise_exception:
			raise
		return False

def getpass_repeat(purpose):
	pass0 = getpass("Enter %s: " % purpose)
	pass1 = getpass("Retype %s: " % purpose)
	if pass0 != pass1:
		error('Passwords do not match!')
	return pass0

def request_current_passphrase(check=True):
	passphrase = getpass("Passphrase for '%s': " % dbdir())
	if check:
		if not check_passphrase(passphrase):
			error('Invalid passphrase!')
	return passphrase

def request_new_passphrase():
	passphrase = getpass_repeat("new passphrase for '%s'" % dbdir())
	return passphrase

def editor(initial_text=""):
	with tempfile.NamedTemporaryFile(suffix=".tmp") as tf:
		tf.write(initial_text.encode("UTF-8"))
		tf.flush()
		if subprocess.call([EDITOR, tf.name]) == 0:
			tf.seek(0)
			new_text = tf.read()
			if new_text != initial_text:
				return new_text.decode("UTF-8")
	return None

def query_yes_no(question, default="yes"):
	valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}

	if default == None:
		prompt = " [y/n] "
	elif default == "yes":
		prompt = " [Y/n] "
	elif default == "no":
		prompt = " [y/N] "
	else:
		raise ValueError("Invalid default answer: '%s'" % default)

	while True:
		sys.stdout.write(question + prompt)
		choice = input().lower()
		if default is not None and choice == '':
			return valid[default]
		elif choice in valid:
			return valid[choice]
		else:
			sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

def blue_text(text):
	if sys.stdout.isatty():
		return '[01;34m' + text + '[00m'
	else:
		return text

def tree(directory, padding=''):
	files = sorted(os.listdir(directory))
	last = len(files) - 1
	for i, f in enumerate(files):
		path = os.path.join(directory, f)
		if i == last:
			if os.path.isdir(path):
				print(padding + '└── ' + blue_text(f))
				tree(path, padding + '    ')
			else:
				print(padding + '└── ' + f)
		else:
			if os.path.isdir(path):
				print(padding + '├── ' + blue_text(f))
				tree(path, padding + '│   ')
			else:
				print(padding + '├── ' + f)

def pwgen(length=DEFAULT_PWLEN, letters=True, digits=True, symbols=False):
	if length < sum(map(int, [letters, digits, symbols])):
		error("Password length %i is too short to contain at least one digit of each desired group." % length)
	alphabet = ""
	if letters:
		alphabet += string.ascii_letters
	if digits:
		alphabet += string.digits
	if symbols:
		alphabet += PWGEN_SYMBOLS
	while True:
		password = ''.join(secrets.choice(alphabet) for i in range(length))
		if letters and not set(password).intersection(string.ascii_letters):
			continue
		if digits and not set(password).intersection(string.digits):
			continue
		if symbols and not set(password).intersection(PWGEN_SYMBOLS):
			continue
		break
	return password



def cmd_init():
	if db_initialized():
		error("Database is already initialized!\nTo change the password use the 'passwd' command.")
	os.makedirs(dbdir(), mode=0o700, exist_ok=True)
	passphrase = request_new_passphrase()
	encrypt("../dbinfo.gpg", passphrase, 'v1')

def cmd_set(entry, ask_overwrite=True, multiline=False, value=None):
	assert not ".." in entry

	os.makedirs(os.path.dirname(entryfile(entry)), mode=0o700, exist_ok=True)

	if os.path.isfile(entryfile(entry)):
		if ask_overwrite:
			if not query_yes_no("An entry already exists for %s. Overwrite it?" % entry, default='no'):
				sys.exit()

	passphrase = request_current_passphrase()

	if not value:
		if os.path.isfile(entryfile(entry)):
			value = decrypt(entry, passphrase)
		else:
			value = ""

		if multiline:
			value = editor(value)
			if not value:
				error("Nothing changed!")
		else:
			value = getpass_repeat("password for %s" % entry)
	encrypt(entry, passphrase, value)

def cmd_gen(length, symbols=False):
	value = pwgen(length=args.length, symbols=symbols)
	cmd_set(args.entry, ask_overwrite=True, value=value)
	print("Generated password: %s" % value)
	# if CLIP_ON_GEN:
	#FIXME: add to clipboard and print notice

def cmd_show(entry):
	assert not ".." in entry

	entrypath = os.path.join(workingdir(), 'db', entry)

	# fallback to ls for incomplete path
	if os.path.isdir(entrypath):
		cmd_ls(entry)
	elif not os.path.isfile(entrypath):
		error("Entry %s not found!" % entry)

	passphrase = request_current_passphrase()

	value = decrypt(entry, passphrase)

	print(value.rstrip("\n"))

def cmd_ls(path="", show_tree=False):
	dbdir = os.path.join(workingdir(), "db")
	path = path.strip('/')
	searchdir = os.path.join(dbdir, path)

	# fallback to show for complete path
	if os.path.isfile(searchdir):
		cmd_show(path)
	elif not os.path.isdir(searchdir):
		error("")

	if show_tree:
		if path:
			print(blue_text(path))
		tree(searchdir)
	else:
		for root, dirs, files in os.walk(searchdir):
			dirs.sort()
			relative_root = root.replace(dbdir, '')
			for filename in sorted(files):
				print(os.path.join(relative_root, filename).strip('/'))

def cmd_passwd():
	passphrase_old = request_current_passphrase()
	passphrase_new = request_new_passphrase()

	print("Changing passphrase for entries...")
	dbdir = os.path.join(workingdir(), "db")
	for root, dirs, files in os.walk(dbdir):
		dirs.sort()
		relative_root = root.replace(dbdir, '')
		for filename in sorted(files):
			entry = os.path.join(relative_root, filename).strip('/')
			print("%s ... " % entry, flush=True, end='')
			try:
				value = decrypt(entry, passphrase_old)
				encrypt(entry, passphrase_new, value)
				print("DONE")
			except CryptoError:
				print("FAILED")
	encrypt("../dbinfo.gpg", passphrase_new, 'v1')

#FIXME:
# main(): (__name__...)
# check for working dir and db and dbinfo.gpg existing
# else default to init (with notice)


#FIXME:
# - entry name validation at a single place


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="A password manager.")
	subparsers = parser.add_subparsers(dest='command', metavar='')

	subparsers.add_parser('init', help='Initialize database')

	parser_ls = subparsers.add_parser('ls', help='Show list of passwords')
	parser_ls.add_argument('path', nargs='?', default='', help='Entry name')
	parser_ls.add_argument('-t', dest='tree', action='store_true', help='Show tree')

	parser_add = subparsers.add_parser('add', help='Add password')
	parser_add.add_argument('entry', help='Entry name')
	parser_add.add_argument('-m', dest='multiline', action='store_true', help='Add multiline password')

	parser_add = subparsers.add_parser('edit', help='Edit password')
	parser_add.add_argument('entry', help='Entry name')

	parser_show = subparsers.add_parser('show', help='Show password')
	parser_show.add_argument('entry', help='Entry name')

	parser_gen = subparsers.add_parser('gen', help='Generate password')
	parser_gen.add_argument('entry', help='Entry name')
	parser_gen.add_argument('-l', dest='length', type=int, default=DEFAULT_PWLEN, help='Password length (default: %i)' % DEFAULT_PWLEN)
	parser_gen.add_argument('-s', dest='symbols', action='store_true', help='Generate password with symbols')

	subparsers.add_parser('passwd', help='Change database password')

	args = parser.parse_args()

	if args.command == 'init':
		cmd_init()
	else:
		if not db_initialized():
			error("Database is not initialized!\nTo initialize the database use the 'init' command.")
		if args.command == 'ls':
			cmd_ls(path=args.path, show_tree=args.tree)
		elif args.command == 'show':
			cmd_show(args.entry)
		elif args.command == 'add':
			cmd_set(args.entry, ask_overwrite=True, multiline=args.multiline)
		elif args.command == 'edit':
			cmd_set(args.entry, ask_overwrite=False, multiline=True)
		elif args.command == 'gen':
			cmd_gen(length=args.length, symbols=args.symbols)
		elif args.command == 'passwd':
			cmd_passwd()
