from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class Server:
    DATABASE_FILE = "database.txt"  # Define the database file path as a class variable
    current_otp_dict = {}

    def __init__(self):
        pass  # No initialization needed for this case

    with open("private.pem", 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())
    with open("public.pem", 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())


    def encrypt_line(line, public_key):
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_data = cipher.encrypt(line.encode('utf-8'))
        return base64.b64encode(encrypted_data).decode('utf-8')  # Base64 ile yazılabilir formatta


    # Deşifreleme fonksiyonu
    def decrypt_line(encrypted_line, private_key):
        cipher = PKCS1_OAEP.new(private_key)
        encrypted_data = base64.b64decode(encrypted_line)
        return cipher.decrypt(encrypted_data).decode('utf-8')


    def get_hashed_password(self, username):
        try:
            with open(Server.DATABASE_FILE, "r") as file:
                # Dosya satırlarını ters sırada oku
                for line in reversed(file.readlines()):
                    line = self.decrypt_line(line,self.private_key)
                    parts = line.strip().split(';')

                    # Eğer username eşleşirse hashed password'u döndür
                    if parts[0] == username:
                        return parts[1]  # Hashed password ikinci sütunda
            return None          # Kullanıcı adı bulunamazsa None döndür
        except FileNotFoundError:
            print("Database file not found.")
            return None


    def username_isExists(self, username):
        try:
            with open(Server.DATABASE_FILE, "r") as file:
                for line in file:
                    line = self.decrypt_line(line,self.private_key)
                    parts = line.strip().split(';')

                    if parts[0] == username:
                        return True      # Kullanıcı adı varsa True döndür
            return False         # Kullanıcı adı bulunmazsa False döndür
        except FileNotFoundError:
            print("Database file not found.")
            return False


    def create_database(self, username, hashed_password):
        with open("database.txt", "a") as file:
            # Write content to the file
            line= username +";"+ hashed_password +";"+ self.current_otp_dict[username] +";"+ str(0)
            encrypted_line = self.encrypt_line(line,self.public_key)
            file.write(encrypted_line + "\n")


    def update_database(self, username, hashed_password, otp_chain, hash_function):
        try:
            with (open(self.DATABASE_FILE, "a") as file):  # Use append mode
                counter = 100 - len(otp_chain[username])
                new_otp = otp_chain[username][-1]

                if hashed_password == self.get_hashed_password(Server, username):

                    if hash_function(new_otp) == self.current_otp_dict[username]:
                        line = username + ";" + hashed_password + ";" + new_otp + ";" + str(counter)
                        encrypted_line = self.encrypt_line(line,self.public_key)
                        file.write(encrypted_line + "\n")
                        self.current_otp_dict[username] = new_otp
                        return True
                return False

        except Exception as e:
            print(f"Error writing to database: {e}")
            return False

