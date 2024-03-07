from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def rsa_encrypt_decrypt():
    key = RSA.generate(2048)
    private_key = key.export_key("PEM")
    public_key = key.publickey().exportKey("PEM")
    message = input("plain text for RSA encryption and decryption:")
    message = str.encode(message)

    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_text = rsa_public_key.encrypt(message)
    # encrypted_text = b64encode(encrypted_text)

    print("your encrypted_text is : {}".format(encrypted_text))

    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(encrypted_text)

    print("your decrypted_text is : {}".format(decrypted_text))


rsa_encrypt_decrypt()
