#!/usr/bin/env python
# encoding: utf-8

# RSA-Cracking Puzzle at http://www.loyalty.org/~schoen/rsa/

from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from os.path import basename
from operator import itemgetter

import getopt
import sys
import os
import glob
import re
import textwrap
import time

# global vars
mySkipList = []
myPTList = []

# taken from http://facthacks.cr.yp.to/euclid.html
def gcd(x,y):
	while x != 0: x,y = y%x,x
	return abs(y)

# taken from https://github.com/hellman/libnum/blob/ad579cc1d43aa8a5b333d8464a941017900c06a6/libnum/common.py#L96
def xgcd(a, b):
	"""
	Extented Euclid GCD algorithm.
	Return (x, y, g) : a * x + b * y = gcd(a, b) = g.
	"""
	if a == 0: return 0, 1, b
	if b == 0: return 1, 0, a

	px, ppx = 0, 1
	py, ppy = 1, 0

	while b:
		q = a // b
		a, b = b, a % b
		x = ppx - q * px
		y = ppy - q * py
		ppx, px = px, x
		ppy, py = py, y

	return ppx, ppy, a

# https://github.com/hellman/libnum/blob/ad579cc1d43aa8a5b333d8464a941017900c06a6/libnum/modular.py#L23
def invmod(a, n):
	"""
	Return 1 / a (mod n).
	@a and @n must be co-primes.
	"""
	if n < 2:
		raise ValueError("modulus must be greater than 1")

	x, y, g = xgcd(a, n)

	if g != 1:
		raise ValueError("no invmod for given @a and @n")
	else:
		return x % n

# Generate RSA Private key
def genRSAPrivateKey(p, q, e, n):
	t = (p-1)*(q-1)
	d = invmod(e,t)
	return RSA.construct((n, e, d, p, q))

# Perform RSA Public Keys sanity checks
def sanity_check(in_file, in_n, in_e, path, verbose, saveKeys):
	for file in glob.glob(path + "/*.pem"):
		if file == in_file:
			continue

		if [file,in_file] in mySkipList:
			# skip re-check
			continue

		# check in_file vs file
		pem = open(file).read()
		k = RSA.importKey(pem)
		n = k.n
		e = k.e

		if in_e == e:
			p = gcd(in_n, n)

			if p != 1:
				# Found RSA Common Factor
				in_p = p
				in_q = in_n / in_p

				# Generate RSA Private Key (in)
				in_priv_key = genRSAPrivateKey(long(in_p), long(in_q), long(in_e), long(in_n))

				q = n / p
				# Generate RSA Private Key (cur)
				priv_key = genRSAPrivateKey(long(p), long(q), long(e), long(n))

				mySkipList.append([in_file,file])

				in_fname = os.path.splitext(basename(in_file))[0]
				fname = os.path.splitext(basename(file))[0]

				f1 = in_fname
				f2 = fname

				if saveKeys:
					# save RSA Private Keys to file
					f = open(path + "/" + in_fname + ".key", "wb");
					f.write(in_priv_key.exportKey());
					f.close();

					f = open(path + "/" + fname + ".key", "wb");
					f.write(priv_key.exportKey());
					f.close();

				in_fname += ".bin"
				fname += ".bin"

				in_ct = open(path + "/" + in_fname, 'rb').read()

				if verbose:
					print "(%s) Ciphertext :\n[[[" % in_fname
					print "\n".join(textwrap.wrap(' '.join(['%02x' % ord(b) for b in in_ct])))
					print "]]]\n"

				dsize = SHA.digest_size
				sentinel = Random.new().read(15+dsize)
				cipher = PKCS1_v1_5.new(in_priv_key)
				in_pt = cipher.decrypt(in_ct, sentinel)

				if verbose:
					print "(%s) Plaintext : %s" % (in_fname,in_pt)
				else:
					sys.stdout.write("#");

				myPTList.append([int(f1),in_pt])

				ct = open(path + "/" + fname, 'rb').read()

				if verbose:
					print "(%s) Ciphertext :\n[[[" % fname
					print "\n".join(textwrap.wrap(' '.join(['%02x' % ord(b) for b in ct])))
					print "]]]\n"

				dsize = SHA.digest_size
				sentinel = Random.new().read(15+dsize)
				cipher = PKCS1_v1_5.new(priv_key)
				pt = cipher.decrypt(ct, sentinel)

				if verbose:
					print "(%s) Plaintext : %s" % (fname,pt)
				else:
					sys.stdout.write("#");

				myPTList.append([int(f2),pt])

def usage(progName):
	h = """USAGE: ./%s <OPTIONS>

OPTIONS:
 -p / --path     : set the challenge data path (required)
 -v / --verbose  : show debug messages
 -s / --saveKeys : save RSA Private Keys to file
 -h / --help     : show this help
""" % basename(progName)
	print(h)

def main():
	verbose = False
	saveKeys = False
	path = ""

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hvsp:", ["help", "verbose", "saveKeys", "path"])
	except getopt.GetoptError as err:
		print str(err)
		usage(sys.argv[0])
		sys.exit(2)

	for o, a in opts:
		if o in ("-p", "--path"):
			if (os.path.isdir(a)):
				path = a;
			else:
				assert False, "wrong 'path' argument, directory does not exist"
		elif o in ("-v", "--verbose"):
			verbose = True
		elif o in ("-s", "--saveKeys"):
			saveKeys = True
		elif o in ("-h", "--help"):
			usage(sys.argv[0])
			sys.exit()
		else:
			assert False, "unhandled option"

	if not path:
		usage(sys.argv[0])
		sys.exit(2)

	# for each pem file perform the sanity checks

	start_time = time.time()
	if not verbose:
		sys.stdout.write("> Analyzing challenge data : ");

	for file in glob.glob(path + "/*.pem"):
		pem = open(file).read()
		k = RSA.importKey(pem)
		n = k.n
		e = k.e
		sanity_check(file, n, e, path, verbose, saveKeys)

	end_time = time.time()
	elapsed = end_time - start_time

	# sort the plaintext messages recovered
	nPT = len(myPTList)
	if nPT > 0:
		if not verbose:
			sys.stdout.write(". Done in %.2f second(s).\n" % elapsed);
		else:
			print(">> Done in %.2f second(s).\n" % elapsed);

		L = sorted(myPTList, key=itemgetter(0))

		print(">> Found %d plaintext(s): \n" % nPT)
		for x in L:
			print("'%d.bin' : %s" % (x[0], x[1]))
	else:
		print("\n!> No plaintext found\n")


if __name__ == "__main__":
	main()
