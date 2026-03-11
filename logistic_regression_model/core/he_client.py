import math

class HEClient:

    def __init__(self, encryptor):
        self.encryptor = encryptor

    def decrypt_and_sigmoid(self, encrypted_z):

        z = self.encryptor.decrypt(encrypted_z)

        return 1 / (1 + math.exp(-z))