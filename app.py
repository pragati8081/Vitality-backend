from flask import Flask, render_template, request,  jsonify,session, redirect,url_for,json
from flask_pymongo import PyMongo
from pymongo import MongoClient
import bcrypt
from datetime import datetime , timedelta
from random import randint
from bson import ObjectId
from werkzeug.security import generate_password_hash
from collections import Counter
import random

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
appointments_collection = mongo.db.appointments  
disease_mapping_collection= mongo.db.disease_mapping
disease_collection = mongo.db.disease
medicine_collection = mongo.db.medicine

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
            session['user_id'] = str(user['_id'])  # ✅ Store as string
            session['user'] = email
            print(f"✅ Login successful! User ID: {session['user_id']}")
            return jsonify({'message': 'Login successful!'}), 200
        else:
            return jsonify({'message': 'Invalid email or password'}), 401

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
        return jsonify({'message': 'User registered successfully!'}), 201

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

# List of 12 deficiencies (multivitamins)
deficiencies = [
    "Vitamin D", "Vitamin B12", "Iron", "Magnesium", 
    "Calcium", "Zinc", "Vitamin A", "Vitamin C", 
    "Folate", "Vitamin K", "Vitamin E", "Copper"
]

# Function to randomly select 4 unique deficiencies
def get_deficiencies():
    return random.sample(deficiencies, 4)

# Load disease mapping from the JSON file (if needed)
def load_disease_mapping():
    try:
        with open('disease_mapping.json', 'r') as f:
            disease_mapping = json.load(f)
            print("Loaded disease mapping:", disease_mapping)  # Debugging line
            return disease_mapping
    except Exception as e:
        print(f"Error loading disease mapping: {e}")
        return {}

# Fetch user responses from MongoDB using the logged-in user ID
def get_user_responses(user_id):
    user_responses = quiz_responses.find_one({"user_id": user_id})
    if user_responses:
        return user_responses
    return None

@app.route('/view_physical_health_responses', methods=['GET'])
def view_physical_health_responses():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    user_id = str(session['user_id'])

    user_quiz = quiz_responses.find_one({"user_id": user_id})

    if not user_quiz or "physical_health" not in user_quiz:
        print("❌ No physical health responses found for user.")
        return jsonify([])

    physical_health_data = user_quiz["physical_health"]
    formatted_responses = []

    disease_mapping = load_disease_mapping()

    for level, questions in physical_health_data.items():
        normalized_level = level.strip().capitalize()

        for question_id, details in questions.items():
            selected_option = str(details.get("answer")).strip()
            question_key = str(question_id).strip().upper()
            timestamp = details.get("timestamp").strftime('%Y-%m-%d %H:%M:%S') if details.get("timestamp") else "N/A"

            formatted = {
                "question_id": question_key,
                "selected_option": selected_option,
                "level": normalized_level,
                "timestamp": timestamp
            }
            formatted_responses.append(formatted)

    recommended_deficiencies = get_deficiencies()

    print("📋 Formatted User Responses:")
    for response in formatted_responses:
        print(f"➤ QID: {response['question_id']}, "
              f"Answer: {response['selected_option']}, "
              f"Level: {response['level']}, "
              f"Time: {response['timestamp']}")

    print(f"🔍 Recommended Deficiencies: {recommended_deficiencies}")

    with open('medicine.json', 'r') as f:
        medicine_data = json.load(f)

    def recommend_multivitamins(deficiencies):
        recommendations = []
        for product in medicine_data:
            if any(deficiency in product.get("ingredients", []) for deficiency in deficiencies):
                recommendations.append(product.get("name"))
            if len(recommendations) >= 4:
                break
        return recommendations

    recommended_vitamins = recommend_multivitamins(recommended_deficiencies)

    print("🧾 Recommended Multivitamin Names:")
    for name in recommended_vitamins:
        print(f"✔️ {name}")

    return render_template('recommendation.html', multivitamins=recommended_vitamins)


@app.route('/recommendation')
def recommendation():
    recommended_deficiencies = get_deficiencies()

    with open('medicine.json', 'r') as f:
        medicine_data = json.load(f)

    def recommend_multivitamins(deficiencies):
        recommendations = []
        for product in medicine_data:
            if any(deficiency in product.get("ingredients", []) for deficiency in deficiencies):
                recommendations.append(product.get("name"))
            if len(recommendations) >= 4:
                break
        return recommendations

    recommended_vitamins = recommend_multivitamins(recommended_deficiencies)

    print("🧾 Recommended Multivitamin Names:")
    for name in recommended_vitamins:
        print(f"✔️ {name}")

    return render_template('recommendation.html', multivitamins=recommended_vitamins)

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

def normalize_time_format(time_str):
    """Ensure time format matches MongoDB stored slots"""
    from datetime import datetime

    try:
        formatted_time = datetime.strptime(time_str, "%I:%M %p").strftime("%I:%M %p")
        return formatted_time
    except ValueError:
        return time_str  # Return as is if formatting fails

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
        print("📩 Full Received Data:", data)

        user_id = session['user_id']
        question_id = data.get('question_id')
        selected_option = data.get('selected_option')
        quiz_category = data.get('quiz_category')  # "mental_health" or "physical_health"
        level = data.get('level')  # Only for physical_health

        # Validate input fields
        if quiz_category == "physical_health":
            required_fields = ['question_id', 'selected_option', 'quiz_category', 'level']
        elif quiz_category == "mental_health":
            required_fields = ['question_id', 'selected_option', 'quiz_category', 'score']
        else:
            print("❌ Error: Invalid quiz_category received")
            return jsonify({"error": "Invalid quiz category"}), 400

        missing_fields = [field for field in required_fields if data.get(field) is None]
        if missing_fields:
            print(f"❌ Error: Missing fields - {missing_fields}")
            return jsonify({"error": f"Incomplete data. Missing: {missing_fields}"}), 400

        # Prepare update
        if quiz_category == "mental_health":
            score = data.get('score', 0)
            update_field = {
                f"mental_health.{question_id}": {
                    "answer": selected_option,
                    "score": score,
                    "timestamp": datetime.utcnow()
                }
            }

        elif quiz_category == "physical_health":
            update_field = {
                f"physical_health.{level}.{question_id}": {
                    "answer": selected_option,
                    "timestamp": datetime.utcnow()
                }
            }

        # Update or insert response in DB
        quiz_responses.update_one(
            {"user_id": str(user_id)},
            {"$set": update_field},
            upsert=True
        )

        print("✅ Response stored successfully!")
        return jsonify({"message": f"{quiz_category.capitalize()} response stored successfully!"}), 201

    except Exception as e:
        print("🚨 Error in /store_quiz_response:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/calculate_score', methods=['GET'])
def calculate_score():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    user_id = str(session['user_id'])
    user_quiz = quiz_responses.find_one({"user_id": user_id})

    # Check if mental_health section exists
    if not user_quiz or "mental_health" not in user_quiz:
        return jsonify({"error": "No mental health responses found"}), 404

    total_score = 0
    for qid, response in user_quiz["mental_health"].items():
        if isinstance(response, dict) and "score" in response:
            total_score += response["score"]

    print("✅ Final Calculated Score:", total_score)
    return jsonify({"total_score": total_score})


@app.route('/details')
def details():
    return render_template('details.html')

@app.route("/get_user_details", methods=["GET"])
def get_user_details():
    user_id = session.get("user_id")
    print(f"🔍 Debug: Session user_id = {user_id}")

    if not user_id:
        return jsonify({"error": "User not logged in"}), 401

    try:
        # Fetch user details from MongoDB
        user = users_collection.find_one(
            {"_id": ObjectId(user_id)},
            {"_id": 0, "name": 1, "first_name": 1, "last_name": 1, "email": 1}
        )

        if user:
            # Ensure 'name' exists by combining first_name and last_name
            user["name"] = user.get("name") or f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()

            print(f"✅ User Data: {user}")  # Debugging log
            return jsonify(user)
        else:
            print("❌ User Not Found in MongoDB")
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print(f"🚨 Error Fetching User: {e}")
        return jsonify({"error": "Invalid user ID format"}), 400

@app.route("/get_therapist", methods=["POST"])
def get_therapist():
    data = request.json
    selected_time = normalize_time_format(data.get("time"))  # Normalize time format

    print(f"📌 Received request for time slot: {selected_time}")  # Debugging log

    therapist = therapists_collection.find_one({"slots": selected_time}, {"_id": 0, "name": 1, "fees": 1})

    if therapist:
        print(f"✅ Assigned Therapist: {therapist}")
        return jsonify(therapist)
    else:
        print("❌ No therapist found for this slot")
        return jsonify({"error": "No therapist available at this time"}), 404


@app.route("/store_appointment", methods=["POST"])
def store_appointment():
    if "user_id" not in session:
        return jsonify({"error": "User not logged in"}), 401

    try:
        data = request.json  
        print("📩 Received Appointment Data:", data)  # Debugging log

        if not data:
            return jsonify({"error": "No data received"}), 400

        # ✅ Check if therapist name is available
        therapist_name = data.get("therapist")
        if not therapist_name:
            return jsonify({"error": "Therapist selection missing"}), 400

        # ✅ Convert `session_date` to Proper Format (YYYY-MM-DD)
        session_date_str = data.get("sessionDate")
        session_date = datetime.strptime(session_date_str, "%Y-%m-%d").strftime("%Y-%m-%d")

        appointment_data = {
            "user_id": session["user_id"],
            "user_name": data.get("fullName"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "session_date": session_date,
            "session_time": data.get("sessionTime"),
            "therapist": therapist_name,  # ✅ Store the correct therapist
            "amount": data.get("amount"),
            "payment_status": "Pending",
            "created_at": datetime.utcnow()
        }

        print("📌 Inserting into MongoDB:", appointment_data)  # Debugging log

        result = appointments_collection.insert_one(appointment_data)

        if result.inserted_id:
            print("✅ Appointment Stored Successfully!")
            return jsonify({"message": "Appointment booked successfully!", "status": "success"}), 201
        else:
            print("❌ Failed to Insert Appointment")
            return jsonify({"error": "Database insert failed"}), 500

    except Exception as e:
        print("🚨 Error Saving Appointment:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/mentalpayment')
def mentalpayment():
    return render_template('mentalpayment.html')

@app.route("/get_appointments", methods=["GET"])
def get_appointments():
    if "user_id" not in session:
        return jsonify([]), 401  # Not logged in
    try:
        user_id = session["user_id"]
        appointments = list(appointments_collection.find({"user_id": user_id}))

        formatted_appointments = []

        for appointment in appointments:
            formatted_appointments.append({
            "username": appointment.get("user_name", "N/A"),
            "therapist_name": appointment.get("therapist", "N/A"),
            "date": appointment.get("session_date", "N/A"),
            "time": appointment.get("session_time", "N/A"),
            "amount": appointment.get("amount", "N/A"),
            "payment_status": appointment.get("payment_status", "N/A")
        })

            print("Fetched Appointments:", formatted_appointments)  # Debugging ke liye
            return jsonify(formatted_appointments)
    
    except Exception as e:
        print("Error fetching appointments:", str(e))
        return jsonify([]), 500


@app.route('/logout')
def logout():
    """Clear the session and log out the user."""
    session.clear()
    return redirect(url_for('login_page'))


if __name__ == '__main__':
    app.run(debug=True)