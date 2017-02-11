import sys,os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization,asymmetric,padding,hashes


def deserialize(private_k,public_k):
	private_key=""
	public_key=""
#private key

	if private_k[-3:]=="pem":
	  with open(private_k, "rb") as key_file:
	     private_key = serialization.load_pem_private_key(
             key_file.read(),
    	     password=None,
             backend=default_backend())
	elif private_k[-3:]=="der":
	  with open(private_k, "rb") as key_file:
	     private_key = serialization.load_der_private_key(
             key_file.read(),
    	     password=None,
             backend=default_backend())
	else:
		print "Private key is not of the form PEM or DER"
		sys.exit()
#public key

	if public_k[-3:]=="pem":
	  with open(public_k, "rb") as key_file:
	     public_key = serialization.load_pem_public_key(
             key_file.read(),
             backend=default_backend())
	elif public_k[-3:]=="der":
	  with open(public_k, "rb") as key_file:
	     public_key = serialization.load_der_public_key(
             key_file.read(),
             backend=default_backend())
	else:
		print "Public key is not of the form PEM or DER"
		sys.exit()	
	return private_key,public_key

def encryptfunc(args):
	try:
		dest_public_key=args[0]
		send_private_key=args[1]
		input_file=args[2]
		output_file=args[3]
	except:
		print "Invalid Input"
		print "Usage: python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file"
		sys.exit()
	backend = default_backend()
	key = os.urandom(32)
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
#pad data
	padder = padding.PKCS7(128).padder()
	padded_data = ""
	with open(input_file, "rb") as in_file:
	     padded_data = padder.update(in_file.read())
	padded_data+=padder.finalize()
#encrypt with AES
	encryptor = cipher.encryptor()
	message= encryptor.update(padded_data) + encryptor.finalize()
#iv and key 
	key_and_iv=str(key)+"#the attached data#"+str(iv)
#load the public and private keys
	private_key,public_key=deserialize(send_private_key,dest_public_key)
#encrypt with destination public key
	rsa_key = public_key.encrypt(key_and_iv,asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
#sign with senders private key	
	signer = private_key.signer(
        asymmetric.padding.PSS(
            mgf=asymmetric.padding.MGF1(hashes.SHA256()),salt_length=asymmetric.padding.PSS.MAX_LENGTH),hashes.SHA256())
	signer.update(message)
	signer.update(key_and_iv)
	signature = signer.finalize()

#writing to file
	with open(output_file, "w") as out_file:
	     out_file.write(message+"#myenc#"+rsa_key+"#myenc#"+signature)
	

def decryptfunc(args):
	try:
		send_public_key=args[1]
		dest_private_key=args[0]
		input_file=args[2]
		output_file=args[3]
	except:
		print "Invalid Input"
		print "python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file"
#load the public and private keys
	private_key,public_key=deserialize(dest_private_key,send_public_key)

#decrypt RSA
	ciphertext =""
	with open(input_file, "r") as in_file:
	     ciphertext =in_file.read()
	message,rsa_key,signature=ciphertext.split("#myenc#")
	public_key = private_key.public_key()
	key_iv= private_key.decrypt(rsa_key,asymmetric.padding.OAEP(mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
	verifier = public_key.verifier(signature,asymmetric.padding.PSS(mgf=asymmetric.padding.MGF1(hashes.SHA256()),salt_length=asymmetric.padding.PSS.MAX_LENGTH),hashes.SHA256())
	verifier.update(message)
	verifier.update(key_iv)
	try:
		verifier.verify()	   	
	except:
		print "Signature cannot be verified"
		sys.exit()    
#decrypt AES
	backend = default_backend()
	key,iv=key_iv.split("#the attached data#")
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	decryptor = cipher.decryptor()
	padded_data=decryptor.update(message) + decryptor.finalize()
	unpadder = padding.PKCS7(128).unpadder()
	data = unpadder.update(padded_data)
	message=data + unpadder.finalize()
#writing to file
	with open(output_file, "wb") as out_file:
	     out_file.write(message)	

args=sys.argv[1:]
if args[0]=='-e':
	encryptfunc(args[1:])
elif args[0]=='-d':
	decryptfunc(args[1:])
