try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    AES_MODE_CBC = modes.CBC
    AES_MODE_ECB = modes.ECB
    AES_MODE_CFB = modes.CFB
    DES_MODE_CBC = modes.CBC
    DES_MODE_ECB = modes.ECB

    class CipherWrapper(object):
        def __init__(self, cipher):
            self._cipher = cipher

        def encrypt(self, data):
            encryptor = self._cipher.encryptor()
            return encryptor.update(data) + encryptor.finalize()

        def decrypt(self, data):
            decryptor = self._cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()

    def create_aes_cipher(key, mode, *args):
        return CipherWrapper(Cipher(algorithms.AES(key), mode(*args)))

    def create_3des_cipher(key, mode, *args):
        return CipherWrapper(Cipher(algorithms.TripleDES(key), mode(*args)))

    def create_des_cipher(key, mode, *args):
        return create_3des_cipher(key*3, mode, *args)

    def create_rc4_cipher(key):
        return CipherWrapper(Cipher(algorithms.ARC4(key), mode=None))

    def aes_ccm_encrypt_and_digest(key, nonce, data, associated_data, tag_length=16):
        aesccm = AESCCM(key, tag_length)
        encrypted_with_tag = aesccm.encrypt(nonce, data, associated_data)
        return encrypted_with_tag[:-tag_length], encrypted_with_tag[-tag_length:]

    def aes_ccm_decrypt_and_verify(key, nonce, data, tag, associated_data, tag_length=16):
        aesccm = AESCCM(key, tag_length)
        return aesccm.decrypt(nonce, data + tag, associated_data)

except ImportError:
    from Cryptodome.Cipher import AES, DES3, ARC4, DES

    AES_MODE_CBC = AES.MODE_CBC
    AES_MODE_ECB = AES.MODE_ECB
    AES_MODE_CFB = AES.MODE_CFB
    DES_MODE_CBC = DES.MODE_CBC
    DES_MODE_ECB = DES.MODE_ECB

    def create_aes_cipher(key, mode, *args):
        return AES.new(key, mode, *args)

    def create_3des_cipher(key, mode, *args):
        return DES3.new(key, mode, *args)

    def create_des_cipher(key, mode, *args):
        return DES.new(key, mode, *args)

    def create_rc4_cipher(key):
        return ARC4.new(key)

    def aes_ccm_encrypt_and_digest(key, nonce, data, associated_data, tag_length=16):
        aesccm = AES.new(key, AES.MODE_CCM,  nonce, mac_len=tag_length)
        aesccm.update(associated_data)
        return aesccm.encrypt_and_digest(data)

    def aes_ccm_decrypt_and_verify(key, nonce, data, tag, associated_data, tag_length=16):
        aesccm = AES.new(key, AES.MODE_CCM,  nonce, mac_len=tag_length)
        aesccm.update(associated_data)
        return aesccm.decrypt_and_verify(data, tag)
