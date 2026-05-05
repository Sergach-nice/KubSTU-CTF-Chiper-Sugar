import hashlib
from Crypto.Cipher import AES
# stream 51 - client
iv51 = bytes.fromhex("516cec24ea85bab5e112ac660bbda80d")
ct51 = bytes.fromhex("3b1989bea3b4e30a0191b333080baacf")
salt = b"a3f7c9b1e2d45608"
# stream 51 - server
iv51s = bytes.fromhex("cf76fca8c660e5e16264f5b45294d350")
ct51s = bytes.fromhex("8b2c837986f5e9f03b4608c5b46f59ebfd19ee1a597ba281224d50dd475b0f9d")

with open("rockyou.txt", "rb") as f:
    for i, line in enumerate(f):
        pwd = line.strip()
        key = hashlib.sha256(pwd + salt).digest()
        try:
            client_cipher = AES.new(key, AES.MODE_CBC, iv51)
            pcm = client_cipher.decrypt(ct51)
            check = pcm[-1]
            if(1 <= check <= 16 and pcm[-check:] == bytes([check])*check):
                server_chiper = AES.new(key, AES.MODE_CBC, iv51s)
                psm = server_chiper.decrypt(ct51s)
                pad = psm[-1]
                print('Password:', pwd.decode('utf-8'))
                print('Client#', pcm[:-check].decode('utf-8'))
                print(psm[:-pad].decode('utf-8'))
                break
        except:
            pass
