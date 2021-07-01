import flask
import flask_login
from flask import render_template
from bs4 import BeautifulSoup
from passlib.hash import sha256_crypt
import os
from datetime import date
import sqlite3
from flask import session
import re

app = flask.Flask(__name__)
app.secret_key = 'super secret string'  # Change this!

login_manager = flask_login.LoginManager()
login_manager.init_app(app)

today = str(date.today())
db_name = 'users.db'
db_dir = './users/'
db_path = db_dir + db_name


conn = sqlite3.connect(db_path)
curs = conn.cursor()
curs.execute("SELECT * FROM users")
rows = curs.fetchall()
curs.close()
conn.commit()
conn.close()  

users = dict() 
for user in rows:
    users[str(user[1])] = {'password' : str(user[2])}


# Our mock database.
#users = {'foo@bar.tld': {'password': 'secret'},'baponkar@gmail.com' : {'password' : '12345'}}


class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(email):
    if email not in users:
        return 

    user = User()
    user.id = email
    return user


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    if email not in users:
        return

    user = User()
    user.id = email

    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    user.is_authenticated = request.form['password'] == users[email]['password']

    return user

@app.route('/')
def hello():
    return "welcome to my login site"
    
@app.route('/logup', methods=['GET', 'POST'])
def logup():
    conn = sqlite3.connect(db_path)
    curs = conn.cursor()
    curs.execute( '''CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY AUTOINCREMENT, username varchar(255) NOT NULL,password varchar(255) NOT NULL)''')
    if flask.request.method == 'GET':
        return render_template('register.html')
    if flask.request.method == 'POST':
        username = flask.request.form['email']
        password1 = flask.request.form['password1']
        password2 = flask.request.form['password2']
        if password1 == password2:
            password = password1
        else:
            return "Two section password not matched"
        #check valid email
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        email_check = bool(re.match(regex, username))
      
        #password check
        password_check = False
        if len(password) >= 8:
            password_check = True
            
        if email_check != True:
            return "Enter a valid uniqe email"
        elif password_check != True:
            return "Enter a valid password"
        elif username in users.keys():
            return "Users already exists."
        else: 
            encrypt_password = sha256_crypt.hash(str(password))
            curs.execute('INSERT INTO users ( username,password) VALUES(?,?)',(str(username),str(encrypt_password)))
            curs.close()
            conn.commit()
            conn.close()
            return "You successfully created \'" + username + "\' as a new user in this site"  

@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET':
        return render_template('login.html')
    
    email = flask.request.form['email']
    entered_password = flask.request.form['password']
   

    conn = sqlite3.connect(db_path)
    curs = conn.cursor()
    curs.execute("SELECT * FROM users WHERE username=?", (email,))
    stored_data = curs.fetchall()
    curs.close()
    conn.commit()
    conn.close()
    
    if len(stored_data) != 0:
        verify = sha256_crypt.verify(entered_password,stored_data[0][2])
   

        if verify:
        #if  flask.request.form['password'] == users[email]['password']:
            user = User()
            user.id = email
            flask_login.login_user(user)        
            return flask.redirect(flask.url_for('protected'))

    return 'Please check username or password'


@app.route('/protected')
@flask_login.login_required
def protected():
    f = open('./templates/profile.html','r')
    html = f.read()
    f.close()
    soup = BeautifulSoup(html,'html.parser')
    find_all_id = soup.find(id='user')
    find_all_id.string.replace_with(" Welcome  " + str(flask_login.current_user.id) + "  !!!!!!")
    
    f = open('./templates/profile.html','w')
    html = f.write(str(soup))
    f.close()
    return render_template('profile.html')


@app.route('/logout')
def logout():
    flask_login.logout_user()
    session.pop('username', None)
    return 'Logged out'


@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'

app.run(debug=True)











