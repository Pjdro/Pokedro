#To run: export FLASK_DEBUG=1 && flask run

from flask import Flask, render_template, request, redirect, session
from cs50 import SQL
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random
import requests

app = Flask(__name__)

db = SQL("sqlite:///pokedro.db")

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

key = b'secretkey1234567'

@app.route("/")
def index():
    random_number = random.randint(1, 1008)
    response = requests.get(f'https://pokeapi.co/api/v2/pokemon/{random_number}/')
    if response.ok:
            # If response is not null, codifies it into a dictionary using json
        index_pkmn = response.json()
        index_image = index_pkmn['sprites']['other']['official-artwork']['front_default']

    scoreboard = db.execute("SELECT longest_streak, users.username FROM trivia JOIN users ON trivia.user_id=users.id WHERE longest_streak > 0 ORDER BY longest_streak DESC LIMIT 5;")
    return render_template("/index.html", index_image=index_image, index_pkmn=index_pkmn, scoreboard=scoreboard)

""" Main Pokemon lookup """
@app.route("/pokemon", methods=['GET', 'POST'])
def pokemon():
    if request.method == "POST":
        pokemon_name = request.form["pokemon_name"]
        if not pokemon_name:
            error_message = 'Plese enter a name or number'
            return render_template("index.html", error_message=error_message)
        # Stores the response using the API
        response = requests.get(f'https://pokeapi.co/api/v2/pokemon/{pokemon_name.lower()}/')
        if not response.ok:
            # Else, prints an error message
            error_message = f"Sorry, we couldn't find Pokemon {pokemon_name} in our database. Please try again"
            return render_template("/error.html", error_message=error_message)

        else:
            # If response is not null, codifies it into a dictionary using json
            pokemon_data = response.json()
            pkmn_data2 = requests.get(f'https://pokeapi.co/api/v2/pokemon-species/{pokemon_name.lower()}/') #Take generation information and previos evolution info, if any
            generation = pkmn_data2.json()
            gen_name = generation['generation']['name'].replace('-', ' ')
            gen = gen_name[11:].upper()
            try:
                prev = generation['evolves_from_species']['name']
                pkmn_data3 = requests.get(f'https://pokeapi.co/api/v2/pokemon/{prev.lower()}/') # If there are previous evolution info, transfer that data to display
                prev_form = pkmn_data3.json()
            except TypeError:
                prev_form = []
            return render_template('pokemon.html', pokemon=pokemon_data, generation=generation, prev_form=prev_form, gen=gen)
    else:
        return render_template("/index.html")
    

""" Register function """   
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "GET":
        return render_template("/register.html")
    else:
        #checks if a username was entered
        if not request.form.get("username"):
            error_message = 'Plese enter a username'
            return render_template("/register.html", error_message=error_message)
        
        #Checks if username has been taken
        rows = db.execute("SELECT username FROM users WHERE username = ? ", request.form.get("username"))
        if len(rows) > 0:
            error_message = 'Sorry, username is taken'
            return render_template("/register.html", error_message=error_message)
        
        #checks if both passwords were entered
        elif not request.form.get("password") or not request.form.get("confirmation"):
            error_message = 'Plese enter a password'
            return render_template("/register.html", error_message=error_message)

        pwd = request.form.get("password")
        special_character = '"!@#$%^&*()-+?_=,.<>/"'
        if len(pwd) < 8 or not any(c in special_character for c in pwd):
            error_message = 'Password needs to contain a minimum of 8 characters and include at least one of the following: !@#$%^&*()-+?_=,.<>/'
            return render_template("/register.html", error_message=error_message)     

        #Checks if passwords match
        elif request.form.get("password") != request.form.get("confirmation"):
            error_message = "Sorry, passwords don't match"
            return render_template("/register.html", error_message=error_message)
        
        #Saves password hash and adds user into DB
        password = generate_password_hash(request.form.get("password"))
        new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), password)

        #Saves the session and goes back to index
        session["user_id"] = new_user
        db.execute("INSERT INTO trivia (user_id, counter, longest_streak) VALUES (?, 0, 0)", session["user_id"])
        return redirect("/")

""" Login function """
@app.route("/login", methods=["GET", "POST"])
def login():

    #erases existing data of previous user login
    session.clear()

    if request.method == "GET":
        return render_template("/login.html")
    

    else:
        #checks if a username was entered
        if not request.form.get("username"):
            error_message = 'Plese enter a username'
            return render_template("/login.html", error_message=error_message)
        
        #checks if password was entered
        elif not request.form.get("password"):
            error_message = 'Plese enter a password'
            return render_template("/login.html", error_message=error_message)
        
        #Checks inside DB for the username/password combination
        rows = db.execute("SELECT * FROM users WHERE username = ? ", request.form.get("username"))

        #If no username was found or the password didn't match, return an error
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            error_message = 'Invalid username and/or password'
            return render_template("/login.html", error_message=error_message)
        
        #If successful, save user id data
        session["user_id"] = rows[0]["id"]

        return redirect("/")
    
""" Logout function """
@app.route("/logout")
def logout():

    #erases existing data of previous user login
    session.clear()

    #Returns to homepage
    return redirect("/")
    

def get_fav():
        favorite_list = db.execute("SELECT favorite_pkmn FROM favorites WHERE user_id = ?", session["user_id"])
        list = {}
        for each in favorite_list:
            search = each['favorite_pkmn']
            query = requests.get(f'https://pokeapi.co/api/v2/pokemon/{search.lower()}/')
            if query.ok:
                response = query.json()
                list[response['name']] = response['sprites']['other']['official-artwork']['front_default']
        return list



""" Favorites function """
@app.route("/favorites", methods=["GET", "POST"])
def favorites():
        
    if request.method == "GET":
        list = get_fav()
        return render_template("/favorites.html", list=list)
    
    else:
        #Reads from form
        favorite = request.form.get("pokemon_name").capitalize()

        #Checks if favorite was already
        favorite_check = db.execute("SELECT favorite_pkmn FROM favorites WHERE favorite_pkmn = ? AND user_id = ? ", favorite, session['user_id'])
        if len(favorite_check) != 0:
            error_message = 'Already in favorites'
            return render_template("/favorites.html", error_message=error_message)
    
        #Adds favorite into DB
        db.execute("INSERT INTO favorites (user_id, favorite_pkmn) VALUES (?, ?)", session["user_id"], favorite)
        list = get_fav()
        return render_template("/favorites.html", list=list)
    


def encrypt_name(name):
    cipher = AES.new(key, AES.MODE_CBC)
    # Convert the name to bytes and pad it
    name_bytes = bytes(name, 'utf-8')
    padded_bytes = pad(name_bytes, AES.block_size)
    # Encrypt the padded bytes
    encrypted_bytes = cipher.encrypt(padded_bytes)
    # Return the Initialization Vector and the encrypted bytes as a tuple
    return cipher.iv + encrypted_bytes



""" Trivia function """
@app.route("/trivia", methods=["GET", "POST"])
def trivia():

    if request.method == "GET":
        random_number = random.randint(1, 1008)
        response = requests.get(f'https://pokeapi.co/api/v2/pokemon/{random_number}/')
        if response.ok:
            # If response is not null, codifies it into a dictionary using json
            index_pkmn = response.json()
            #Send the value to be cyphered before being sent into HTML so no cheat is allowed
            crypted = encrypt_name(index_pkmn['name']).hex()
            query = db.execute("SELECT counter, longest_streak FROM trivia WHERE user_id = ?", session["user_id"])
            streak = int(query[0]['longest_streak'])
            counter = int(query[0]['counter'])
            return render_template("/trivia.html", index_pkmn=index_pkmn, streak=streak, counter=counter, crypted=crypted)
    
    else:

        name_entered = request.form.get("trivia")
        name_entered = name_entered.lower().strip()

        #decyphering the correct answer
        encrypted_name = bytes.fromhex(request.form.get("result"))
        cipher = AES.new(key, AES.MODE_CBC, iv=encrypted_name[:16])
        encrypted_bytes = encrypted_name[16:]
        # Decrypt the encrypted bytes and unpad the result
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        correct_answer = decrypted_bytes.decode('utf-8')

        if name_entered != correct_answer:
            db.execute("UPDATE trivia SET counter=0 WHERE user_id = ?", session["user_id"])
            message = 'incorrect'
            return render_template("/result.html", message=message)
        else:
            db.execute("UPDATE trivia SET counter=counter+1 WHERE user_id = ?", session["user_id"])
            cntr = db.execute("SELECT counter FROM trivia WHERE user_id = ?", session["user_id"])
            counter = int(cntr[0]['counter'])
            strk = db.execute("SELECT longest_streak FROM trivia WHERE user_id = ?", session["user_id"])
            streak = int(strk[0]['longest_streak'])
            if counter > streak:
                db.execute("UPDATE trivia SET longest_streak=counter WHERE user_id = ?", session["user_id"])
            message = 'correct'
            return render_template("/result.html", message=message)



if __name__ == "main":
    app.run(debug=True)