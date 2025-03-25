from flask import Flask, render_template, request,  jsonify,session, redirect,url_for
from flask_pymongo import PyMongo
import bcrypt
from datetime import datetime , timedelta
from random import randint
from bson import ObjectId
from werkzeug.security import generate_password_hash
from bson import ObjectId

app = Flask(__name__)

# ✅ Set Secret Key First
app.config['SECRET_KEY'] = 'a1b2c3d4e5f6'

# ✅ Configure MongoDB Connection
app.config["MONGO_URI"] = "mongodb://localhost:27017/vitality"

# ✅ Initialize PyMongo
mongo = PyMongo(app)

# ✅ Access Collections
quiz_responses = mongo.db.quiz_responses
users_collection = mongo.db.users  
therapists_collection = mongo.db.therapists
appointments_collection = mongo.db.appointments  # Collection to store therapist bookings

otp_storage = {} 
@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/booksession')
def booksession():
    return render_template('booksession.html')

@app.route('/profilepage')
def profilepage():
    if 'user_id' not in session:  # Ensure user is logged in
        return redirect(url_for('login_page'))
    return render_template('profilepage.html')

@app.route('/get_profile', methods=['GET'])
def get_profile():
    try:
        if 'user_id' not in session:
            return jsonify({"error": "User not logged in"}), 401

        user = mongo.db.users.find_one(
            {"_id": ObjectId(session['user_id'])},
            {"_id": 0, "password": 0}
        )

        if user:
            # If 'name' exists, return it; otherwise, combine first_name and last_name
            user["name"] = user.get("name") or f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
            return jsonify(user)
        else:
            return jsonify({"error": "Profile not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
@app.route('/save_profile', methods=['POST'])
def save_profile():
    try:
        if 'user_id' not in session:
            return jsonify({"error": "User not logged in"}), 401

        data = request.json

        # Validate data
        if not data.get("username") or not data.get("address") or not data.get("phone"):
            return jsonify({"error": "All fields are required"}), 400

        # Update the user record
        mongo.db.users.update_one(
            {"_id": ObjectId(session['user_id'])},
            {"$set": {
                "username": data["username"],
                "address": data["address"],
                "phone": data["phone"]
            }}
        )

        return jsonify({"message": "Profile updated successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/take_quiz', methods=['GET', 'POST'])
def take_quiz():
    if 'user_id' not in session:  # Redirect to login if not authenticated
        return redirect(url_for('login_page'))
    return redirect(url_for('option'))  # Redirect to quiz options

@app.route('/check_login')
def check_login():
    return jsonify({'logged_in': 'user_id' in session})

# Route to serve the reset password page based on the selected method
@app.route("/reset_password/<method>")
def reset_password_page(method):
    if method not in ["email", "phone"]:
        return "Invalid method", 400  # Ensure only email or phone is used
    return render_template("reset_password.html", method=method)

# Route to send OTP to email or phone
@app.route('/send_otp')
def send_otp():
    method = request.args.get('method')
    user_input = request.args.get('input')
    user = users_collection.find_one({'email': user_input} if method == 'email' else {'phone': user_input})

    if user:
        otp = str(randint(1000, 9999))
        otp_storage[user_input] = {"otp": otp, "expires_at": datetime.utcnow() + timedelta(minutes=5)}
        print(f"OTP for {user_input}: {otp}")  # For testing; replace with actual email/SMS sending
        return jsonify({'success': True, 'message': f'OTP sent to {user_input}!'})
    else:
        return jsonify({'success': False, 'message': 'User not found. Please enter a registered email/phone!'})
    
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'GET':
        method = request.args.get('method')
        user_input = request.args.get('input')
        return render_template('verify_otp.html', method=method, user_input=user_input)

    # POST request for OTP verification
    data = request.json
    user_input = data.get('input')
    otp = data.get('otp')

    stored_otp_data = otp_storage.get(user_input)
    if stored_otp_data:
        if stored_otp_data["otp"] == otp:
            session['reset_user'] = user_input
            return jsonify({'success': True, 'message': 'OTP verified!'})
    
    return jsonify({'success': False, 'message': 'Invalid OTP!'})


# Route to update password after OTP verification
@app.route("/update_password", methods=["POST"])
def update_password():
    try:
        if 'user_id' not in session:
            return jsonify({"success": False, "message": "User not logged in"}), 401

        data = request.json
        current_password = data.get("current_password")
        new_password = data.get("password")

        if not new_password:
            return jsonify({"success": False, "message": "New password is required"}), 400

        user = users_collection.find_one({"_id": ObjectId(session['user_id'])})

        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        if current_password:
            if "password" not in user:
                return jsonify({"success": False, "message": "Password not found"}), 400

            if not bcrypt.checkpw(current_password.encode('utf-8'), user["password"]):
                return jsonify({"success": False, "message": "Incorrect current password"}), 400

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        users_collection.update_one(
            {"_id": ObjectId(session['user_id'])},
            {"$set": {"password": hashed_password}}
        )

        return jsonify({"success": True, "message": "Password updated successfully!"})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/new_password")
def new_password_page():
    user_input = request.args.get("input")
    return render_template("new_password.html", user_input=user_input)


@app.route('/')
def home():
    return render_template('home.html')  # Serve home page on app start

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.get_json()
        email = data['email']
        password = data['password']

        user = mongo.db.users.find_one({'email': email})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session.clear()
            session['user_id'] = str(user['_id'])
            session['user'] = email
            print("✅ Login successful!")
            return jsonify({'message': 'Login successful!'}), 200
        else:
            return jsonify({'message': 'Invalid email or password'}), 401  # 🔹 Better error message

    return render_template('login.html')

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

@app.route('/submitpage')
def submitpage():
    return render_template('submitpage.html')

@app.route("/get_therapist_details", methods=["GET"])
def get_therapist_details():
    try:
        if 'user_id' not in session:
            return jsonify({"error": "User not logged in"}), 401

        user_id = session['user_id']
        appointment = mongo.db.appointments.find_one({"user_id": user_id})

        if not appointment:
            return jsonify({"error": "No therapy appointments found"}), 404

        therapist = mongo.db.therapists.find_one({"_id": appointment["therapist_id"]})

        if not therapist:
            return jsonify({"error": "Therapist details not found"}), 404

        return jsonify({
            "therapist_name": therapist["name"],
            "specialization": therapist["specialization"],
            "date": appointment["date"],
            "time": appointment["time"],
            "amount_paid": appointment["amount_paid"]
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/details')
def details():
    return render_template('details.html')

@app.route('/mentalpayment')
def mentalpayment():
    return render_template('mentalpayment.html')

@app.route("/confirm_booking", methods=["POST"])
def confirm_booking():
    user_name = request.form["name"]
    email = request.form["email"]
    phone = request.form["phone"]
    therapist_name = request.form["therapist"]
    session_date = request.form["date"]
    session_time = request.form["time"]
    amount_paid = request.form["amount"]

    # Store in MongoDB
    mongo.db.appointments.insert_one({
        "user_name": user_name,
        "email": email,
        "phone": phone,
        "therapist": therapist_name,
        "date": session_date,
        "time": session_time,
        "amount_paid": amount_paid
    })

    return redirect("/booking_success")

# Route to display booking success page
@app.route("/booking_success")
def booking_success():
    return "Booking confirmed! Your session has been scheduled."

@app.route('/vitalitycheckout')
def vitalitycheckout():
    return render_template('vitalitycheckout.html')

@app.route('/store_quiz_response', methods=['POST'])
def store_quiz_response():
    if 'user_id' not in session:
        print("❌ User not logged in")
        return jsonify({"error": "User not logged in"}), 401

    try:
        data = request.json
        print("📩 Received Data:", data)  # ✅ Debugging log

        user_id = session['user_id']
        question_id = data.get('question_id')
        selected_option = data.get('selected_option')
        score = data.get('score', 0)  # Default score is 0 if missing
        quiz_category = data.get('quiz_category')

        if not question_id or not selected_option or not quiz_category:
            print("❌ Error: Incomplete data received!")
            return jsonify({"error": "Incomplete data"}), 400

        # ✅ Debugging before saving to MongoDB
        print(f"📝 Storing: user_id={user_id}, question_id={question_id}, answer={selected_option}, score={score}")

        # ✅ Ensure correct MongoDB structure
        result = quiz_responses.update_one(
            {"user_id": str(user_id), "quiz_category": quiz_category},
            {"$set": {
                f"responses.{question_id}": {
                    "answer": selected_option,  
                    "score": score,  
                    "timestamp": datetime.utcnow()
                }
            }},
            upsert=True
        )

        # ✅ Debugging MongoDB Update
        print("✅ MongoDB Update Result:", result.raw_result)

        return jsonify({"message": "Response stored successfully!"}), 201

    except Exception as e:
        print("🚨 Error in /store_quiz_response:", str(e))  # ✅ Log error
        return jsonify({"error": str(e)}), 500
    
@app.route('/calculate_score', methods=['GET'])
def calculate_score():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    user_id = session['user_id']

    # ✅ Fetch user responses from MongoDB
    user_quiz = quiz_responses.find_one({"user_id": str(user_id), "quiz_category": "mental_health"})

    if not user_quiz or "responses" not in user_quiz:
        return jsonify({"error": "No responses found"}), 404

    total_score = sum(response.get("score", 0) for response in user_quiz["responses"].values())

    # ✅ Return the total score
    return jsonify({"total_score": total_score})

@app.route('/logout')
def logout():
    """Clear the session and log out the user."""
    session.clear()
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(debug=True)