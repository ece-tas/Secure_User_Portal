from flask import Flask, render_template, redirect, url_for, request, flash
import re
from Crypto.Hash import SHA256

from Server import Server

# http://127.0.0.1:5000 (local address)
# http://10.225.185.242:5000 (network access)

SERVER_URL = "http://127.0.0.1:5000"

app = Flask(__name__)
app.secret_key = 'supersecretkey'
server = Server()
dict = {}


# Helper function to hash passwords
def hash_password(password):
    hash_obj = SHA256.new()
    hash_obj.update(password.encode())

    return hash_obj.hexdigest()


def validate_username(username):
    # Regular expression to check that the username contains only letters (no numbers, no special characters)
    if not re.match("^[a-zA-Z0-9]+$", username) and (username in dict):
        flash("Username must contain only letters!", "error")
        return False
    return True


def validate_password(password):
    if len(password) <= 6:
        flash("Password must be longer than 6 characters!", "error")
        return False
    return True


def create_OTP(username, seed, count, max_count=100):
    # Base case: stop recursion when count reaches max_count
    if count >= max_count:
        return seed  # Return the final OTP value
    dict[username].append(hash_password(seed))
    # Recursive step: hash the seed and increment count
    return create_OTP(username, hash_password(seed), count + 1, max_count)


# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    count = 0
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        val_password = request.form['val_password']

        hashed_password = hash_password(password)
        dict[username] = []

        if Server.username_isExists(Server, username):
            return render_template('register.html')

        elif not (validate_username(username) and validate_password(password) and val_password == password):
            flash(
                "Invalid username or password. Username must only contain letters, and password must be longer than 6 characters.",
                "error")
            return render_template('register.html')

        seed = password
        create_OTP(username, seed, count, max_count=100)
        Server.current_otp_dict[username] = dict.get(username)[-1]
        dict[username].pop()

        Server.create_database(Server, username, hashed_password)

        flash("Registration successful!", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not Server.username_isExists(Server, username):
            return redirect(url_for('register'))

        if Server.update_database(Server, username, hash_password(password), dict, hash_password):
            flash("Login successful!", "success")
            dict[username].pop()

            if len(dict[username]) == 0:
                count = 0
                seed = password
                create_OTP(username, seed, count, max_count=100)
                Server.current_otp_dict[username] = dict.get(username)[-1]
                dict[username].pop()
                return redirect(url_for('welcome', username=username))

            return redirect(url_for('welcome', username=username))
        else:
            return render_template('login.html')

    return render_template('login.html')


# Welcome Route
@app.route('/welcome')
def welcome():
    username = request.args.get('username')     # Get the username from the query string
    if not username:
        return redirect(url_for('login'))        # Redirect to login if username is missing
    return render_template('welcome.html', username=username)    # Pass username to template


@app.route('/')
def main_screen():
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


