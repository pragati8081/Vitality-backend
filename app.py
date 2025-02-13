from flask import Flask, render_template, request,  jsonify,session, redirect,url_for
from flask_pymongo import PyMongo
import bcrypt

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/vitality"
mongo = PyMongo(app)

app.config['SECRET_KEY'] = 'a1b2c3d4e5f6'

@app.route('/')
def home():
    return render_template('home.html')  # Serve home page on app start

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        # Parse login form data
        data = request.get_json()
        email = data['email']
        password = data['password']

        # Look up user in database
        user = mongo.db.users.find_one({'email': email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user'] = email  # Store user email in session
            print("Login successful!")
            return jsonify({'message': 'Login successful!'}), 200

        else: return jsonify({'message': 'User not registered'}), 401
    return render_template('login.html')  # Serve login page for GET requests

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    if request.method == 'POST':
        # Parse signup form data
        data = request.get_json()
        first_name = data['first_name']
        last_name = data['last_name']
        email = data['email']
        password = data['password']

        # Check if the user already exists
        if mongo.db.users.find_one({'email': email}):
            return jsonify({'message': 'User already exists!'}), 400

        # Hash the password and save the user
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        mongo.db.users.insert_one({
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': hashed_password
        })
        return jsonify({'message': 'User registered successfully!'}), 400

    return render_template('signup.html')  # Serve signup page for GET requests

@app.route('/options', methods=['GET', 'POST'])
def option():
    if 'user' in session:
        return render_template('option.html')
    else:
        return redirect(url_for('login_page'))  # Redirect to log in if not logged in

@app.route('/take_quiz', methods=['GET', 'POST'])
def take_quiz():
    if 'user' in session:
        return redirect(url_for('option'))  # Redirect to option.html if logged in
    return redirect(url_for('login_page'))  # Redirect to login page if not logged in

@app.route('/basic')  # This route will be used to access the page
def basic():
    return render_template('basic.html')

@app.route('/basicQ1')
def basic_q1():
    return render_template('basicQ1.html')

@app.route('/basicQ2')
def basic_q2():
    return render_template('basicQ2.html')

@app.route('/basicQ3')
def basic_q3():
    return render_template('basicQ3.html')

@app.route('/basicQ4')
def basic_q4():
    return render_template('basicQ4.html')

@app.route('/basicQ5')
def basic_q5():
    return render_template('basicQ5.html')

@app.route('/basicQ6')
def basic_q6():
    return render_template('basicQ6.html')

@app.route('/basicQ7')
def basic_q7():
    return render_template('basicQ7.html')

@app.route('/basicQ8')
def basic_q8():
    return render_template('basicQ8.html')

@app.route('/basicQ9')
def basic_q9():
    return render_template('basicQ9.html')

@app.route('/basicQ10')
def basic_q10():
    return render_template('basicQ10.html')

@app.route('/basicQ11')
def basic_q11():
    return render_template('basicQ11.html')

@app.route('/basicQ12')
def basic_q12():
    return render_template('basicQ12.html')

@app.route('/basicQ13')
def basic_q13():
    return render_template('basicQ13.html')

@app.route('/basicQ14')
def basic_q14():
    return render_template('basicQ14.html')

@app.route('/basicQ15')
def basic_q15():
    return render_template('basicQ15.html')

@app.route('/basicQ16')
def basic_q16():
    return render_template('basicQ16.html')

@app.route('/basicQ17')
def basic_q17():
    return render_template('basicQ17.html')

@app.route('/basicQ18')
def basic_q18():
    return render_template('basicQ18.html')

@app.route('/basicQ19')
def basic_q19():
    return render_template('basicQ19.html')

@app.route('/basicQ20')
def basic_q20():
    return render_template('basicQ20.html')

@app.route('/basicQ21')
def basic_q21():
    return render_template('basicQ21.html')

@app.route('/basicQ22')
def basic_q22():
    return render_template('basicQ22.html')

@app.route('/basicQ23')
def basic_q23():
    return render_template('basicQ23.html')

@app.route('/basicQ24')
def basic_q24():
    return render_template('basicQ24.html')

@app.route('/basicQ25')
def basic_q25():
    return render_template('basicQ25.html')

@app.route('/basicQ26')
def basic_q26():
    return render_template('basicQ26.html')

@app.route('/basicQ27')
def basic_q27():
    return render_template('basicQ27.html')

@app.route('/basicQ28')
def basic_q28():
    return render_template('basicQ28.html')

@app.route('/basicQ29')
def basic_q29():
    return render_template('basicQ29.html')

@app.route('/basicQ30')
def basic_q30():
    return render_template('basicQ30.html')

@app.route('/lifestyle')
def lifestyles():
    return render_template('lifestyle.html')

@app.route('/lifestyleQ1')
def lifestyle_q1():
    return render_template('lifestyleQ1.html')

@app.route('/lifestyleQ2')
def lifestyle_q2():
    return render_template('lifestyleQ2.html')

@app.route('/lifestyleQ3')
def lifestyle_q3():
    return render_template('lifestyleQ3.html')

@app.route('/lifestyleQ4')
def lifestyle_q4():
    return render_template('lifestyleQ4.html')

@app.route('/lifestyleQ5')
def lifestyle_q5():
    return render_template('lifestyleQ5.html')

@app.route('/lifestyleQ6')
def lifestyle_q6():
    return render_template('lifestyleQ6.html')

@app.route('/lifestyleQ7')
def lifestyle_q7():
    return render_template('lifestyleQ7.html')

@app.route('/lifestyleQ8')
def lifestyle_q8():
    return render_template('lifestyleQ8.html')

@app.route('/lifestyleQ9')
def lifestyle_q9():
    return render_template('lifestyleQ9.html')

@app.route('/lifestyleQ10')
def lifestyle_q10():
    return render_template('lifestyleQ10.html')

@app.route('/lifestyleQ11')
def lifestyle_q11():
    return render_template('lifestyleQ11.html')

@app.route('/lifestyleQ12')
def lifestyle_q12():
    return render_template('lifestyleQ12.html')

@app.route('/lifestyleQ13')
def lifestyle_q13():
    return render_template('lifestyleQ13.html')

@app.route('/lifestyleQ14')
def lifestyle_q14():
    return render_template('lifestyleQ14.html')

@app.route('/lifestyleQ15')
def lifestyle_q15():
    return render_template('lifestyleQ15.html')

@app.route('/lifestyleQ16')
def lifestyle_q16():
    return render_template('lifestyleQ16.html')

@app.route('/lifestyleQ17')
def lifestyle_q17():
    return render_template('lifestyleQ17.html')

@app.route('/lifestyleQ18')
def lifestyle_q18():
    return render_template('lifestyleQ18.html')

@app.route('/lifestyleQ19')
def lifestyle_q19():
    return render_template('lifestyleQ19.html')

@app.route('/lifestyleQ20')
def lifestyle_q20():
    return render_template('lifestyleQ20.html')

@app.route('/lifestyleQ21')
def lifestyle_q21():
    return render_template('lifestyleQ21.html')

@app.route('/lifestyleQ22')
def lifestyle_q22():
    return render_template('lifestyleQ22.html')

@app.route('/lifestyleQ23')
def lifestyle_q23():
    return render_template('lifestyleQ23.html')

@app.route('/lifestyleQ24')
def lifestyle_q24():
    return render_template('lifestyleQ24.html')

@app.route('/lifestyleQ25')
def lifestyle_q25():
    return render_template('lifestyleQ25.html')

@app.route('/lifestyleQ26')
def lifestyle_q26():
    return render_template('lifestyleQ26.html')

@app.route('/lifestyleQ27')
def lifestyle_q27():
    return render_template('lifestyleQ27.html')

@app.route('/lifestyleQ28')
def lifestyle_q28():
    return render_template('lifestyleQ28.html')

@app.route('/lifestyleQ29')
def lifestyle_q29():
    return render_template('lifestyleQ29.html')

@app.route('/lifestyleQ30')
def lifestyle_q30():
    return render_template('lifestyleQ30.html')

@app.route('/goals')
def goals():
    return render_template('goals.html')

@app.route('/goalsQ1')
def goals_q1():
    return render_template('goalsQ1.html')

@app.route('/goalsQ2')
def goals_q2():
    return render_template('goalsQ2.html')

@app.route('/goalsQ3')
def goals_q3():
    return render_template('goalsQ3.html')

@app.route('/goalsQ4')
def goals_q4():
    return render_template('goalsQ4.html')

@app.route('/goalsQ5')
def goals_q5():
    return render_template('goalsQ5.html')

@app.route('/goalsQ6')
def goals_q6():
    return render_template('goalsQ6.html')

@app.route('/goalsQ7')
def goals_q7():
    return render_template('goalsQ7.html')

@app.route('/goalsQ8')
def goals_q8():
    return render_template('goalsQ8.html')

@app.route('/goalsQ9')
def goals_q9():
    return render_template('goalsQ9.html')

@app.route('/goalsQ10')
def goals_q10():
    return render_template('goalsQ10.html')

@app.route('/goalsQ11')
def goals_q11():
    return render_template('goalsQ11.html')

@app.route('/goalsQ12')
def goals_q12():
    return render_template('goalsQ12.html')

@app.route('/goalsQ13')
def goals_q13():
    return render_template('goalsQ13.html')

@app.route('/goalsQ14')
def goals_q14():
    return render_template('goalsQ14.html')

@app.route('/goalsQ15')
def goals_q15():
    return render_template('goalsQ15.html')

@app.route('/goalsQ16')
def goals_q16():
    return render_template('goalsQ16.html')

@app.route('/goalsQ17')
def goals_q17():
    return render_template('goalsQ17.html')

@app.route('/goalsQ18')
def goals_q18():
    return render_template('goalsQ18.html')

@app.route('/goalsQ19')
def goals_q19():
    return render_template('goalsQ19.html')

@app.route('/goalsQ20')
def goals_q20():
    return render_template('goalsQ20.html')

@app.route('/goalsQ21')
def goals_q21():
    return render_template('goalsQ21.html')

@app.route('/goalsQ22')
def goals_q22():
    return render_template('goalsQ22.html')

@app.route('/goalsQ23')
def goals_q23():
    return render_template('goalsQ23.html')

@app.route('/goalsQ24')
def goals_q24():
    return render_template('goalsQ24.html')

@app.route('/goalsQ25')
def goals_q25():
    return render_template('goalsQ25.html')

@app.route('/goalsQ26')
def goals_q26():
    return render_template('goalsQ26.html')

@app.route('/goalsQ27')
def goals_q27():
    return render_template('goalsQ27.html')

@app.route('/goalsQ28')
def goals_q28():
    return render_template('goalsQ28.html')

@app.route('/goalsQ29')
def goals_q29():
    return render_template('goalsQ29.html')

@app.route('/goalsQ30')
def goals_q30():
    return render_template('goalsQ30.html')

if __name__ == '__main__':
    app.run(debug=True)