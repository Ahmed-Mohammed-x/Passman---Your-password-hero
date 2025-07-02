# app.py - All python code was made in 1 file because splitting it made it difficult to focus
# and hard to implement and understand



# Core library imports
import base64
import os
import re
import secrets
import sqlite3
import string
from functools import wraps
import time

# Cryptography imports to hash and encrypt passwords
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# Flask imports for web based program
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Flask configuration
app = Flask(__name__)

# Secret key to protect tampering with data and I made it random as it safer.
# In production use, one permanent secret will be used as having it on random or different ones will invalidate previous sessions by users
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())

# Database to store the passwords
app.config['DATABASE'] = 'passwords.db'

# Cookie security to data of the session secure "must be true in production" (but to avoid issues during development, set to false)
app.config['SESSION_COOKIE_SECURE'] = False

# To help protect against cross site scripting attacks (XSS)
app.config['SESSION_COOKIE_HTTPONLY'] = True

# A security measure best practiced specially in bank apps.
# I don't think users need more than 10 minutes to add, remove, or view their passwords.
app.config['PERMANENT_SESSION_LIFETIME'] = 7200  # 2 hours for professor to tinker around if desired :)


# Initialize database, pw = password/s
def init_database():
    with sqlite3.connect(app.config['DATABASE']) as connection:
        connection.executescript('''
                                 -- Create users table!
                                 CREATE TABLE IF NOT EXISTS users
                                 (
                                     user_id       INTEGER PRIMARY KEY,                --helps connection both tables, unique
                                     username      VARCHAR(200) UNIQUE NOT NULL,       --unique as we also need it to make sure we don't have multiple acc with the same username
                                     password_hash VARCHAR(256)        NOT NULL,       -- store hashed pw
                                     salt          VARCHAR(32)         NOT NULL,       -- store salf of hashed pw
                                     created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP --store acc creation time the same time it happened
                                 );
                                 -- Create Passwords table
                                 CREATE TABLE IF NOT EXISTS passwords
                                 (
                                     password_id        INTEGER PRIMARY KEY,                 --unique for each pw
                                     user_id            INTEGER,                             --foreign key to connect both tables
                                     site_name          VARCHAR(200) NOT NULL,               --some may want to save a long site name
                                     username           VARCHAR(200) NOT NULL,               --Username :)
                                     encrypted_password BLOB         NOT NULL,               -- data of encrypted pw 
                                     iv                 BLOB         NOT NULL,               --to avoid identical encrypted data of pw and help decrypt
                                     created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP, --creation of entry
                                     updated_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP, --creation of updated entry
                                     FOREIGN KEY (user_id) REFERENCES users (user_id)        -- foreign key to connect both tables and ensures users exist
                                 );
                                 ''')


# Decorator function for authentication
def login_required(f):
    @wraps(f)  # checks if user_id is there or not(metadata protection)
    def decorated_function(*args, **kwargs):  # args, **kwargs could be anything but are standard :)
        if 'user_id' not in session:
            # redirects to login page
            return redirect(url_for('login'))
        return f(*args, **kwargs)  # to enter if user_id exists

    return decorated_function  # return the decorator function. Could be named anything


# Password functions timeee!

# change master passwords of users to encrypted hashed keys with salt
def generate_master_key(master_password, salt):
    # Generate encrypted key from password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # a very strong hashing algorithm
        length=32,
        salt=salt,
        iterations=100000,
    )
    # change password to bytes and then encode for storage
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


# could be named anything but used encrypt password for clarity, pw = password
def encrypt_pw(pw, secret_key):
    f = Fernet(secret_key)
    return f.encrypt(pw.encode())


# // Same comment as above, clarity of functions and easy calling
def decrypt_pw(encrypted_pw, secret_key):
    f = Fernet(secret_key)
    return f.decrypt(encrypted_pw).decode()


# Helps the user to generate a strong password
def generate_strong_password(lengthofchar=16, specialchar=True):
    chars = string.ascii_letters + string.digits  # could be changed
    if specialchar:
        chars += string.punctuation

    while True:
        password = ''.join(secrets.choice(chars) for _ in range(lengthofchar))

        # If statements to check different parameters for evaluating strength
        if (any(c.islower() for c in password)  # lowercase check
                and any(c.isupper() for c in password)  # uppercase check
                and sum(c.isdigit() for c in password) >= 3  # At least 3 numbers
                and (not specialchar or any(c in string.punctuation for c in password))):
            # Generates password when conditions are met
            return password


# checks the strength of the password
def password_strength_checker(password):
    # Let's see what this password has going for it
    password_parameters = {
        'length_size': len(password) >= 12,  # 12+ chars is decent
        'uppercase': any(c.isupper() for c in password),
        'lowercase': any(c.islower() for c in password),
        'has_numbers': any(c.isdigit() for c in password),
        'has_characters': any(c in string.punctuation for c in password)  # !@#$
    }

    # Count if all parameters add up
    total_parameters = sum(password_parameters.values())

    # Feedback
    security_level = [
        "very weak. change immediately!",
        "Kinda weak",
        "Okay",
        "Very strong",
        "Perfect"
    ][min(total_parameters, 4)]

    # Send back the brutal truth
    return {
        'score': total_parameters,
        'details': password_parameters,
        'verdict': security_level
    }


# protection from XSS attacks
def suspicious_input(input_text):
    sus_input = r'[<>\'"&]'

    # checking if there's anything suspicious :P
    if re.search(sus_input, input_text):

        # Clean the input
        good_text = re.sub(sus_input, '', input_text)

        # unnecessary double check
        if re.search(sus_input, good_text):
            # unlikely to happen :)
            return "Input suspicious alert!"

        return good_text

    # If input passed the check-up
    return input_text


# tracks login attempts to make sure it's not an intruder
# Could be longer like an hour or day depending on company requirements but this is a demo
login_attempts = {}
Max_attempts = 5
Timeout = 60  # 1 minutes


# Routes
# Starting page to direct users accordingly!
@app.route('/')
def landing_page():
    # First-time setup: make sure our database exists (for server logs and devs)
    if not os.path.exists(app.config['DATABASE']):
        print("First time launching the website, setting up the database, please wait ^_^")
        init_database()

    # Check if this user already exists
    if 'user_id' in session:
        #
        return redirect(url_for('pw_safe'))

    # New user, redirecting to login page
    return redirect(url_for('login'))


# user signup
@app.route('/register', methods=['GET', 'POST'])
def new_user():
    # if statement to check if the user already have an account
    if 'user_id' in session:
        return redirect(url_for('pw_safe'))

    # User signing up
    if request.method == 'POST':
        username = suspicious_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        # Input validation
        if not username or not password:
            flash('Please add Both the username and password', 'danger')
            return render_template('register.html')

        # check the password's strength
        password_missing = []
        if len(password) < 8:
            password_missing.append("at least 8 characters")
        if not re.search(r'[A-Z]', password):
            password_missing.append("an uppercase letter")
        if not re.search(r'[a-z]', password):
            password_missing.append("a lowercase letter")
        if not re.search(r'[0-9]', password):
            password_missing.append("a number")

        if password_missing:
            flash(f"Your password needs {', '.join(password_missing)}", 'danger')
            return render_template('register.html')

        # Create salt and hash
        salt_pw = secrets.token_hex(16)
        hash_pw = generate_password_hash(password + salt_pw)

        try:
            with sqlite3.connect(app.config['DATABASE']) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    flash('Username already exists', 'danger')
                    return render_template('register.html')

                # Add User and detail to the Database
                cursor.execute(
                    "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                    (username, hash_pw, salt_pw)
                )
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))

        # Error while registering
        except Exception as error:
            flash(f'Registration failed: {str(error)}', 'danger')

    # return to registration page
    return render_template('register.html')


# Loging in functions and implementation timeee
@app.route('/login', methods=['GET', 'POST'])
def login():
    # if they are logged in, take them to pw_safe page
    if 'user_id' in session:
        return redirect(url_for('pw_safe'))

    # if someone wants to log in, check their username and password
    if request.method == 'POST':
        username = suspicious_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        user_ip = request.remote_addr

        # Check if they attempted too many times
        if user_ip in login_attempts and login_attempts[user_ip]['attempts'] >= Max_attempts:
            if time.time() - login_attempts[user_ip]['timestamp'] < Timeout:
                flash(f'Too many failed attempts. Try again later.', 'danger')
                return render_template('login.html')
            else:
                # Reset if Timeout duration has passed
                login_attempts.pop(user_ip)

        try:

            # Open database to check user info
            with sqlite3.connect(app.config['DATABASE']) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()

                # If they exist, they can log in
                if user and check_password_hash(user['password_hash'], password + user['salt']):
                    if user_ip in login_attempts:
                        login_attempts.pop(user_ip)

                    # save data
                    session['user_id'] = user['user_id']
                    session['username'] = user['username']

                    # Generate encrypted key from master password
                    encrypted_key = generate_master_key(password, user['salt'].encode())
                    session['encryption_key'] = encrypted_key.decode()

                    # to return to the pw_safe page
                    return redirect(url_for('pw_safe'))
                else:

                    # count failed attempts
                    if user_ip not in login_attempts:
                        login_attempts[user_ip] = {'attempts': 1, 'timestamp': time.time()}
                    else:
                        login_attempts[user_ip]['attempts'] += 1
                        login_attempts[user_ip]['timestamp'] = time.time()
                    flash('Invalid username or password', 'danger')
        except Exception as error:
            flash(f'Login error. Something went wrong: {str(error)}', 'danger')

    # Return to login page
    return render_template('login.html')


# Log out timeee
@app.route('/logout')
def logout_user():
    # removes session data
    session.clear()

    flash('You have been logged out successfully. Your passwords are safe with Passman ;)', 'info')

    # return to login page
    return redirect(url_for('login'))


# Password's safe where they can be modified
@app.route('/pw_safe')
@login_required
def pw_safe():
    try:
        with sqlite3.connect(app.config['DATABASE']) as connect:

            # Finding our passwords ordered by site's name
            connect.row_factory = sqlite3.Row
            cursor = connect.cursor()
            cursor.execute(
                "SELECT * FROM passwords WHERE user_id = ? ORDER BY site_name",
                (session['user_id'],)
            )
            passwords = cursor.fetchall()

        # users can now see the password
        return render_template('pw_safe.html', passwords=passwords)


    except Exception as error:

        # Raising error if the user couldn't access the passwords
        flash(f'An error occurred  while retrieving passwords: {str(error)}', 'danger')

        # Shows an empty page if there was an error or no passwords were saved yet
        return render_template('pw_safe.html', passwords=[])


# Setting passwords and web handling
@app.route('/add_pw', methods=['GET', 'POST'])
# only users who are logged in can enter here ;)
@login_required
def add_pw():
    # if someone wants to save a new password, we validate it and clean any suspicious inputs
    if request.method == 'POST':
        site_name = suspicious_input(request.form.get('site_name', ''))
        username = suspicious_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        # Validate the password
        if not site_name or not username or not password:
            flash('make sure to fill out all fields please', 'danger')
            return render_template('add_pw.html')

        try:

            # Get the encryption key from the session
            encryption_key = session.get('encryption_key')

            if not encryption_key:
                flash('Session has unfortunately expired. Try logging in again.', 'danger')
                return redirect(url_for('login'))

            # Encrypt the password hehe
            encrypted_password = encrypt_pw(password, encryption_key.encode())
            iv = os.urandom(16)  # Initialization vector (very important)

            # Save to the database aka safe
            with sqlite3.connect(app.config['DATABASE']) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO passwords (user_id, site_name, username, encrypted_password, iv)
                       VALUES (?, ?, ?, ?, ?)""",
                    (session['user_id'], site_name, username, encrypted_password, iv)
                )
                conn.commit()

            flash('Password is now safe ;)', 'success')
            return redirect(url_for('pw_safe'))
        except Exception as error:
            flash(f'Error while adding your password! =_=: {str(error)}', 'danger')

    return render_template('add_pw.html')


# This is to view ur safe
@app.route('/get/<int:password_id>')
# Are you logged in? welcome back!

@login_required
# function to get the passwords
def get_pw(password_id):
    try:

        # connect to your database and find the requested password if it matches user_id and pw_id
        with sqlite3.connect(app.config['DATABASE']) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM passwords WHERE password_id = ? AND user_id = ?",
                (password_id, session['user_id'])
            )
            password = cursor.fetchone()

        # if not found, print:
        if not password:
            return jsonify({'error': 'Oops! Password is not here :<'}), 404

        # Get the encryption key from the session and if not they have to log in again
        encryption_key = session.get('encryption_key')
        if not encryption_key:
            return jsonify({'error': 'Session expired. Please log in again.'}), 401

        # Decrypt the password to show it to the user
        decrypted_password = decrypt_pw(password['encrypted_password'], encryption_key.encode())

        # return the valuable information to the user
        return jsonify({
            'site_name': password['site_name'],
            'username': password['username'],
            'password': decrypted_password
        })
    except Exception as error:
        return jsonify({'error': str(error)}), 500


# helps you delete ur passwords that you don't to keep or change it since an update function wasn't made
@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    try:
        # Open the database and delete the chosen password if it matched th logged-in user_id and pw_id
        with sqlite3.connect(app.config['DATABASE']) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM passwords WHERE password_id = ? AND user_id = ?",
                (password_id, session['user_id'])
            )
            conn.commit()

            # To check if it actually got deleted
            if cursor.rowcount > 0:
                flash('Password has been removed.'
                      ' Dont forget to add the site pw again if you changed your password!',
                      'success')

            else:
                flash('Password not found', 'danger')
    except Exception as error:
        # handling errors
        flash(f'Error occurred while deleting password. Oops!: {str(error)}', 'danger')

    return redirect(url_for('pw_safe'))


# Generating strong and secure passwords for users :)
@app.route('/generate-password')
# ofc only logged-in users can access!
@login_required

# function to make sure
def generate_password_route():
    length = int(request.args.get('length', 16))
    use_special = request.args.get('special', 'true').lower() == 'true'

    password = generate_strong_password(length, use_special)
    strength = password_strength_checker(password)

    return jsonify({
        'password': password,
        'strength': strength['verdict'],
        'score': strength['score']
    })


if __name__ == '__main__':

    if not os.path.exists(app.config['DATABASE']):
        init_database()
    app.run(debug=True, port=5000)
