# Email-Encryption
Encrypting files to be sent over email

For encryption :

python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file

For decryption :

python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file


The symmertric encryption used is AES , the encryption mode used i s CBC.The key size used is 32 bytes and iv is 16 bytes.
The Asymmetric encryption used is RSA.It is not textbook RSA so we have to pad the data in the end.
First we generate the key and iv for the AES.
Then we encrypt the data/file with AES using CBC mode.
Then we are calculating the senders private and receivers public keys from the der/pem files given to us
Receivers public key is used to encrypt the AES key and iv.
Then senders private key is used for the signature.This signature takes the key and iv and also the AES encrypted message.
These are then dumped to a file and sent to the receiver.
On the receiving end senders public and receivers private keys from the der/pem files are calculated.
Signature is verified with the senders public key.
Then Key and iv are decrypted with the receivers private key.
In the end the message is decrypted from the AES keyand iv .
