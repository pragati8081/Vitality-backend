from flask import Flask, render_template, request,  jsonify,session, redirect,url_for
from flask_pymongo import PyMongo
import bcrypt
from datetime import datetime 
from random import randint

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/vitality"
mongo = PyMongo(app)
quiz_responses = mongo.db.quiz_responses
app.config['SECRET_KEY'] = 'a1b2c3d4e5f6'

otp_storage = {} 
@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/booksession')
def booksession():
    return render_template('booksession.html')


# Route to serve the reset password page based on the selected method
@app.route('/reset_password/<method>')
def reset_password(method):
    if method in ['email', 'phone']:
        return render_template('reset_password.html', method=method)
    else:
        return redirect('/forgot_password')

# Route to send OTP to email or phone
@app.route('/send_otp')
def send_otp():
    method = request.args.get('method')
    user_input = request.args.get('input')
    user = None

    # Find user by email or phone
    if method == 'email':
        user = mongo.db.users.find_one({'email': user_input})
    elif method == 'phone':
        user = mongo.db.users.find_one({'phone': user_input})

    if user:
        otp = str(randint(1000, 9999))
        otp_storage[user_input] = otp
        print(f"OTP for {user_input}: {otp}")  # For testing; replace with actual email/SMS sending
        return jsonify({'success': True, 'message': 'OTP sent successfully!'})
    else:
        return jsonify({'success': False, 'message': 'User not found!'})

# Route to verify OTP
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'GET':
        method = request.args.get('method')
        user_input = request.args.get('input')
        return render_template('verify_otp.html', method=method, user_input=user_input)

    # POST request to verify OTP
    data = request.get_json()
    user_input = data['input']
    otp = data['otp']

    if otp_storage.get(user_input) == otp:
        session['reset_user'] = user_input
        return jsonify({'success': True, 'message': 'OTP verified!'})
    else:
        return jsonify({'success': False, 'message': 'Invalid OTP!'})

# Route to update password after OTP verification
@app.route('/update_password', methods=['POST'])
def update_password():
    if 'reset_user' in session:
        data = request.get_json()
        new_password = data['new_password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        # Update password in the database
        mongo.db.users.update_one(
            {'$or': [{'email': session['reset_user']}, {'phone': session['reset_user']}]},
            {'$set': {'password': hashed_password}}
        )
        session.pop('reset_user', None)  # Clear session
        return jsonify({'success': True, 'message': 'Password updated successfully!'})
    return jsonify({'success': False, 'message': 'Unauthorized access!'})

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
            session.clear()  
            session['user_id'] = str(user['_id']) 
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

@app.route('/check_login')
def check_login():
    if 'user_id' in session:  # Assuming you use session to track logged-in users
        print("Session Data:", session)  # 🔍 Debugging line
        return {'logged_in': True}
     
    else:
        return {'logged_in': False}
        
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

@app.route('/profilepage')
def profilepage():
    return render_template('profilepage.html')

@app.route('/physicalhome')
def physicalhome():
    return render_template('physicalhome.html')

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

@app.route('/recommendation')
def recommendation():
    return render_template('recommendation.html')

@app.route('/mentalhome')
def mentalhome():
    return render_template('mentalhome.html')

@app.route('/mental1')
def mental1():
    return render_template('mental1.html')

@app.route('/mental2')
def mental2():
    return render_template('mental2.html')

@app.route('/mental3')
def mental3():
    return render_template('mental3.html')

@app.route('/mental4')
def mental4():
    return render_template('mental4.html')

@app.route('/mental5')
def mental5():
    return render_template('mental5.html')

@app.route('/mental6')
def mental6():
    return render_template('mental6.html')

@app.route('/mental7')
def mental7():
    return render_template('mental7.html')

@app.route('/mental8')
def mental8():
    return render_template('mental8.html')

@app.route('/mental9')
def mental9():
    return render_template('mental9.html')

@app.route('/mental10')
def mental10():
    return render_template('mental10.html')

@app.route('/mental11')
def mental11():
    return render_template('mental11.html')

@app.route('/mental12')
def mental12():
    return render_template('mental12.html')

@app.route('/mental13')
def mental13():
    return render_template('mental13.html')

@app.route('/mental14')
def mental14():
    return render_template('mental14.html')

@app.route('/mental15')
def mental15():
    return render_template('mental15.html')

@app.route('/mental16')
def mental16():
    return render_template('mental16.html')

@app.route('/mental17')
def mental17():
    return render_template('mental17.html')

@app.route('/mental18')
def mental18():
    return render_template('mental18.html')

@app.route('/mental19')
def mental19():
    return render_template('mental19.html')

@app.route('/mental20')
def mental20():
    return render_template('mental20.html')

@app.route('/mental21')
def mental21():
    return render_template('mental21.html')

@app.route('/mental22')
def mental22():
    return render_template('mental22.html')

@app.route('/mental23')
def mental23():
    return render_template('mental23.html')

@app.route('/mental24')
def mental24():
    return render_template('mental24.html')

@app.route('/mental25')
def mental25():
    return render_template('mental25.html')

@app.route('/mental26')
def mental26():
    return render_template('mental26.html')

@app.route('/mental27')
def mental27():
    return render_template('mental27.html')

@app.route('/mental28')
def mental28():
    return render_template('mental28.html')

@app.route('/mental29')
def mental29():
    return render_template('mental29.html')

@app.route('/mental30')
def mental30():
    return render_template('mental30.html')

@app.route('/mental31')
def mental31():
    return render_template('mental31.html')

@app.route('/mental32')
def mental32():
    return render_template('mental32.html')

@app.route('/mental33')
def mental33():
    return render_template('mental33.html')

@app.route('/mental34')
def mental34():
    return render_template('mental34.html')

@app.route('/mental35')
def mental35():
    return render_template('mental35.html')

@app.route('/mental36')
def mental36():
    return render_template('mental36.html')

@app.route('/mental37')
def mental37():
    return render_template('mental37.html')

@app.route('/mental38')
def mental38():
    return render_template('mental38.html')

@app.route('/mental39')
def mental39():
    return render_template('mental39.html')

@app.route('/mental41')
def mental41():
    return render_template('mental41.html')

@app.route('/submitpage')
def submitpage():
    return render_template('submitpage.html')

@app.route('/details')
def details():
    return render_template('details.html')

@app.route('/mentalpayment')
def mentalpayment():
    return render_template('mentalpayment.html')

@app.route('/vitalitycheckout')
def vitalitycheckout():
    return render_template('vitalitycheckout.html')

@app.route('/store_quiz_response', methods=['POST'])
def store_quiz_response():
    print("Session Data:", session)  # ✅ Debugging log

    if 'user_id' not in session:
        print("Error: User not logged in")
        return jsonify({"error": "User not logged in"}), 401

    try:
        data = request.json
        print("Received Data:", data)  # ✅ Debugging log

        user_id = session['user_id']
        question_id = data.get('question_id')
        selected_option = data.get('selected_option')
        quiz_category = data.get('quiz_category')

        if not question_id or not selected_option or not quiz_category:
            print("Error: Incomplete data received!")
            return jsonify({"error": "Incomplete data"}), 400

        # ✅ Find the existing quiz response document for the user
        user_quiz = quiz_responses.find_one({"user_id": str(user_id), "quiz_category": quiz_category})

        if user_quiz:
            # ✅ Update existing document by adding new response
            quiz_responses.update_one(
                {"user_id": str(user_id), "quiz_category": quiz_category},
                {"$set": {f"responses.{question_id}": selected_option}}
            )
            print(f"Updated quiz response for {user_id} in {quiz_category}")
        else:
            # ✅ Create a new document if this is the first response
            quiz_data = {
                "user_id": str(user_id),
                "quiz_category": quiz_category,
                "responses": {question_id: selected_option},
                "timestamp": datetime.utcnow()
            }
            quiz_responses.insert_one(quiz_data)
            print(f"Created new quiz response for {user_id} in {quiz_category}")

        return jsonify({"message": "Response stored successfully"}), 201

    except Exception as e:
        print("Error in /store_quiz_response:", str(e))  # ✅ Log error
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/save_quiz_response', methods=['POST'])
def save_quiz_response():
    if 'user_id' not in session:
        return {"error": "User not logged in"}, 401

    user_id = session['user_id']
    data = request.json  

    quiz_category = data.get('quiz_category')
    level = data.get('level')
    answers = data.get('answers')

    if not quiz_category or not level or not answers:
        return {"error": "Missing data"}, 400

    response_data = {
        "level": level,
        "answers": answers,
        "timestamp": datetime.utcnow()
    }

    # 🔥 Ensure a single document per user & category
    mongo.db.quiz_responses.update_one(
        {"user_id": user_id, "quiz_category": quiz_category},  # Match user and category
        {
            "$setOnInsert": {"user_id": user_id, "quiz_category": quiz_category},  # Create only if it doesn't exist
            "$push": {"responses": response_data}  # Add new quiz responses to the array
        },
        upsert=True  # Ensure a document is created if none exists
    )

    return {"message": "Response saved successfully"}, 200

if __name__ == '__main__':
    app.run(debug=True)
