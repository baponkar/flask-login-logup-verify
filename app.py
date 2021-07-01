import flask
import flask_login
from flask import render_template
from bs4 import BeautifulSoup
from passlib.hash import sha256_crypt
import os
from datetime import date
import sqlite3



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
print ("rows : " + str(rows)) 
users = dict() 
for user in rows:
    users[str(user[1])] = {'password' : str(user[2])}
print(users)
# Our mock database.
#users = {'foo@bar.tld': {'password': 'secret'}}


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
        password = flask.request.form['password']
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
    stored_pass = curs.fetchall()
    curs.close()
    conn.commit()
    conn.close()
    print("stored password : " + str(stored_pass[0][2]))
    print("entered password : " + entered_password)
    
    verify = sha256_crypt.verify(entered_password,stored_pass[0][2])
   
    print(verify)
    if  verify:
        user = User()
        user.id = email
        flask_login.login_user(user)        
        return flask.redirect(flask.url_for('protected'))

    return 'Please check username or password'


@app.route('/protected')
@flask_login.login_required
def protected():
    f = open('/home/bapon/Desktop/login_project/templates/profile.html','r')
    html = f.read()
    f.close()
    soup = BeautifulSoup(html,'html.parser')
    find_all_id = soup.find(id='user')
    find_all_id.string.replace_with(" Welcome  " + str(flask_login.current_user.id) + "  !!!!!!")
    
    f = open('/home/bapon/Desktop/login_project/templates/profile.html','w')
    html = f.write(str(soup))
    f.close()
    #print(soup)
    return render_template('profile.html')


@app.route('/logout')
def logout():
    flask_login.logout_user()
    return 'Logged out'


@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'

app.run()











