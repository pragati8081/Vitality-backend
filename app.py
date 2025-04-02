from flask import Flask, render_template, request,  jsonify,session, redirect,url_for,json
from flask_pymongo import PyMongo
from pymongo import MongoClient
import bcrypt
from datetime import datetime , timedelta
from random import randint
from bson import ObjectId
from werkzeug.security import generate_password_hash
from collections import Counter

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
disease_mapping_collection = mongo.db.disease_mapping
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

def get_user_quiz_responses():
    """Fetch the logged-in user's quiz responses from MongoDB"""
    if "user_id" not in session:
        print("🚨 No user logged in.")
        return None  

    user_id = session["user_id"]
    print(f"🔍 Fetching quiz responses for user_id: {user_id}")

    user_responses = mongo.db.quiz_responses.find_one({
        "user_id": user_id, 
        "quiz_category": "physical_health"
    })

    if not user_responses:
        print(f"🚨 No quiz responses found for user_id: {user_id}")
        return None

    print("✅ User response found:", user_responses)
    return user_responses  # ✅ Return the actual responses instead of boolean


def detect_deficiencies(responses):
    """Analyze quiz responses to detect deficiencies based on user inputs."""
    print("DEBUG: Full User Response ->", responses)  

    deficiencies = []

    if not responses:
        print("🚨 No responses found for deficiency detection.")
        return deficiencies

    print("DEBUG: Available categories:", responses.get("Physical Health", {}).keys())

    physical_health = responses.get("Physical Health", {})
    basic = physical_health.get("Basic", {})
    lifestyle = physical_health.get("LifeStyle", {})

    # Helper function to retrieve and validate answers
    def get_answer(question_id, category):
        """Fetch and validate an answer for a given question."""
        answer = category.get(question_id, {}).get("answer")
        return str(answer) if answer is not None else None 

    # Mapping Functions
    def apply_mapping(question_id, category, mapping):
        """Fetch the answer and apply the mapping if valid."""
        answer = get_answer(question_id, category)
        return mapping.get(answer) if answer in mapping else None  # ✅ Corrected synta

    # 1. Age Mapping
    age_mapping = {
        "1": "Iron & Zinc Deficiency (Growth Phase)",
        "2": "General Nutritional Maintenance",
        "3": "General Nutritional Maintenance",
        "4": "General Nutritional Maintenance",
        "5": "Calcium & Vitamin D Deficiency (Age Factor)"
    }
    deficiencies.append(apply_mapping("Q1", basic, age_mapping))

    # 2. Gender Mapping
    gender_mapping = {
        "1": "Zinc Deficiency (Muscle Recovery)",
        "2": "Iron Deficiency (Higher Risk in Women)",
        "3": "Individualized Nutrient Needs"
    }
    deficiencies.append(apply_mapping("Q2", basic, gender_mapping))

    # 3. Height Mapping
    height_mapping = {
        "1": "Bone Health Risk (Short Stature)",
        "2": "Normal Growth Potential",
        "3": "Normal Growth Potential",
        "4": "Higher Caloric & Protein Needs"
    }
    deficiencies.append(apply_mapping("Q3", basic, height_mapping))

    # 4. Weight Mapping
    weight_mapping = {
        "1": "Malnutrition Risk (Underweight)",
        "2": "Balanced Weight Maintenance",
        "3": "Balanced Weight Maintenance",
        "4": "Balanced Weight Maintenance",
        "5": "Obesity Risk & Metabolic Imbalance"
    }
    deficiencies.append(apply_mapping("Q4", basic, weight_mapping))

    # 5. Allergies
    if get_answer("Q5", basic) == "2":
        deficiencies.append("Dietary Restrictions May Cause Nutrient Deficiency")

    # 6. Medical Conditions
    medical_mapping = {
        "PCOS/PCOD": "Hormonal Imbalance Risk (PCOS/PCOD)",
        "Thyroid Disorder": "Iodine Deficiency (Thyroid Issue)",
        "Diabetes": "Blood Sugar Imbalance Risk",
        "Other": "Potential Nutritional Deficiencies (Medical Condition)"
    }
    deficiencies.append(apply_mapping("Q6", basic, medical_mapping))

    # 7. Medication Effects
    if get_answer("Q7", basic) == "Yes":
        deficiencies.append("Possible Nutrient Absorption Issues")

    # 8. Doctor Visits
    doctor_visit_mapping = {
        "1": "Unmonitored Health Risks",
        "2": "Moderate Health Monitoring",
        "3": "Regular Checkups Maintained",
        "4": "Well-Monitored Health"
    }
    deficiencies.append(apply_mapping("Q8", basic, doctor_visit_mapping))

    # 9. Diet Type
    diet_mapping = {
        "1": "Vitamin B12 & Iron Deficiency (Diet Restriction)",
        "2": "Vitamin B12 & Iron Deficiency (Diet Restriction)",
        "3": "Folate Deficiency Risk",
        "4": "Calcium & Vitamin D Deficiency",
        "5": "No Dietary Deficiencies"
    }
    deficiencies.append(apply_mapping("Q9", basic, diet_mapping))

    # 10. Energy Levels
    energy_mapping = {
        "1": "Iron & Vitamin D Deficiency (Low Energy)",
        "2": "Balanced Energy Levels",
        "3": "Good Energy Balance"
    }
    deficiencies.append(apply_mapping("Q10", basic, energy_mapping))

    # --- Lifestyle-Based Deficiencies ---
    lifestyle_mappings = {
        "Q1": {  # Sleep Mapping
            "1": ["Fatigue", "Weak Immunity", "Low Focus"],
            "2": ["Mild Fatigue"],
            "3": ["Healthy Sleep"],
            "4": ["Oversleeping Risks"]
        },
        "Q2": {  # Exercise Frequency
            "1": ["Weak Muscles", "Low Endurance"],
            "2": ["Moderate Fitness"],
            "3": ["Good Fitness"],
            "4": ["High Energy Levels"]
        },
        "Q3": {  # Exercise Type
            "1": ["Heart Health Benefits"],
            "2": ["Muscle Growth"],
            "3": ["Flexibility & Stress Reduction"],
            "4": ["Weak Muscles", "Low Stamina"]
        },
        "Q4": {  # Stress Levels
            "1": ["Balanced Health"],
            "2": ["Mild Anxiety Risks"],
            "3": ["High Cortisol, Anxiety"],
            "4": ["Severe Stress, Fatigue"]
        },
        "Q5": {  # Fast Food Consumption
            "1": ["Good Nutrition"],
            "2": ["Moderate Junk Food Intake"],
            "3": ["Risk of Deficiencies"],
            "4": ["High Cholesterol, Poor Nutrition"]
        },
        "Q6": {  # Water Intake
            "1": ["Dehydration Risk", "Low Energy"],
            "2": ["Adequate Hydration"],
            "3": ["Optimal Hydration"],
            "4": ["High Hydration"]
        },
        "Q7": {  # Screen Time
            "1": ["Minimal Eye Strain"],
            "2": ["Moderate Eye Strain"],
            "3": ["Risk of Digital Eye Fatigue"],
            "4": ["High Risk of Eye Fatigue, Poor Sleep"]
        },
        "Q8": {  # Alcohol Consumption
            "1": ["Good Liver Health"],
            "2": ["Potential Health Risks"],
            "3": ["Liver Stress, Dehydration Risks"]
        },
        "Q9": {  # Smoking
            "1": ["Lung Health Risks", "Heart Disease Risk"],
            "2": ["Healthy Lungs"]
        },
        "Q10": {  # Relaxation/Self-Care
            "1": ["Increased Stress Levels"],
            "2": ["Moderate Stress Management"],
            "3": ["Good Mental Balance"],
            "4": ["Optimal Mental Health"]
        }
    }

    for question, mapping in lifestyle_mappings.items():
        answer = get_answer(question, lifestyle)
        if answer in mapping:
            deficiencies.extend(mapping[answer])

    # Remove None values & duplicates
    deficiencies = list(set(filter(None, deficiencies)))
    print(f"🔍 Available Deficiencies in Dict: {list(deficiencies.keys())}")
    print("DEBUG: Final Deficiency List Before Returning ->", deficiencies)
    
    return deficiencies

def refine_deficiencies(detected_deficiencies):
    priority_order = [
        "Iron & Vitamin D Deficiency (Low Energy)",    
        "Vitamin B12 & Iron Deficiency (Diet Restriction)",  
        "Zinc Deficiency (Muscle Recovery)",  
        "Weak Immunity",  
        "Fatigue",  
        "Low Focus",  
        "Weak Muscles",  
        "Low Endurance",  
        "Heart Health Benefits",  
        "Moderate Junk Food Intake",  
        "Unmonitored Health Risks",  
        "Balanced Weight Maintenance",  
        "General Nutritional Maintenance",  
        "Normal Growth Potential",  
        "Balanced Health"  # Only if no other deficiencies exist
    ]
    
    if not detected_deficiencies:
        print("⚠️ No deficiencies detected, assigning default deficiency")
        return ["Vitamin D Deficiency"]  # ✅ Assign a default deficiency only if the list is empty

    # Remove contradictory results
    if "Balanced Health" in detected_deficiencies:
        detected_deficiencies = [d for d in detected_deficiencies if d != "Balanced Health"]
    
    # Remove redundancy & group deficiencies
    grouped_deficiencies = set()
    for deficiency in detected_deficiencies:
        if "Iron" in deficiency or "Vitamin B12" in deficiency:
            grouped_deficiencies.add("Iron & Vitamin Deficiency")
        elif "Zinc" in deficiency:
            grouped_deficiencies.add("Zinc Deficiency")
        elif "Immunity" in deficiency:
            grouped_deficiencies.add("Weak Immunity")
        else:
            grouped_deficiencies.add(deficiency)

    # Sort deficiencies based on priority
    sorted_deficiencies = sorted(grouped_deficiencies, key=lambda x: priority_order.index(x) if x in priority_order else float('inf'))  # ✅ Prevent errors if deficiency is not in the list

    # Return only the top 4 deficiencies
    return sorted_deficiencies[:4]


@app.route("/analyze_quiz", methods=["GET"])
def analyze_quiz():
    """Fetch user responses, detect deficiencies, and return results."""
    responses = get_user_quiz_responses()
    
    if not responses:
        print("🚨 No quiz responses found for the user.")
        return jsonify({"deficiencies": [], "message": "No quiz responses found"}), 404
    
    deficiencies = detect_deficiencies(responses) or []  # ✅ Ensure a list is always returned
    print(f"✅ Analysis completed! User Deficiencies: {deficiencies}")
    
    return jsonify({"deficiencies": deficiencies})


@app.route('/recommendation', methods=['GET'])
def recommendation():
    """Fetch recommended multivitamins from user responses and display them."""
    if 'user_id' not in session:
        print("🚨 User not logged in.")
        return jsonify({"error": "User not logged in"}), 401  

    user_id = session['user_id']
    print(f"🔍 Fetching quiz responses for user_id: {user_id}")

    user_responses = mongo.db.quiz_responses.find_one({"user_id": user_id})

    if not user_responses:
        print(f"🚨 No quiz responses found for user_id: {user_id}")
        return jsonify({"error": "No quiz responses found"}), 404

    # Extract recommended multivitamin names
    recommended_multivitamins = user_responses.get("recommended_multivitamins", [])[:4]

    print("✅ Recommended Multivitamin Names:", recommended_multivitamins)  # Debugging Line

    return render_template('recommendation.html', multivitamins=recommended_multivitamins)

def map_deficiencies_to_multivitamins(deficiencies):
    """Maps deficiencies to recommended multivitamins from the provided list."""
    
    deficiency_to_multivitamin = {
    "Weak Muscles": [
        {"name": "GNC Mega Men Sport", "image": "{{ url_for('static', filename='images/a.jpeg') }}"},
        {"name": "MuscleBlaze MB-Vite Multivitamin", "image": "{{ url_for('static', filename='images/b.jpeg') }}"},
        {"name": "Optimum Nutrition Opti-Men", "image": "{{ url_for('static', filename='images/c.jpeg') }}"}
    ],
    "Low Endurance": [
        {"name": "Revital H Men Multivitamin", "image":"{{ url_for('static', filename='images/d.jpeg') }}"},
        {"name": "GNC Mega Men Sport", "image":"{{ url_for('static', filename='images/a.jpeg') }}"},
        {"name": "Swisse Ultivite Men's Multivitamin", "image":"{{ url_for('static', filename='images/e.jpeg') }}"}
    ],
    "Unmonitored Health Risks": [
        {"name": "Centrum Men Multivitamin", "image": "{{ url_for('static', filename='images/f.jpeg') }}"},
        {"name": "HealthKart HK Vitals Multivitamin", "image": "{{ url_for('static', filename='images/g.jpeg') }}"}
    ],
    "Zinc Deficiency (Muscle Recovery)": [
        {"name": "Zincovit Tablet", "image": "{{ url_for('static', filename='images/h.jpeg') }}"},
        {"name": "Supradyn Daily Multivitamin", "image": "{{ url_for('static', filename='images/i.jpeg') }}"}
    ],
    "Normal Growth Potential": [
        {"name": "Pure Nutrition Men's Multi Vitamin", "image": "{{ url_for('static', filename='images/j.jpeg') }}"},
        {"name": "Healthvit Cenvitan Men Multivitamin", "image": "{{ url_for('static', filename='images/k.jpeg') }}"}
    ],
    "Balanced Health": [
        {"name": "Centrum Women Multivitamin", "image": "{{ url_for('static', filename='images/l.jpeg') }}"},
        {"name": "Centrum Men Multivitamin", "image":  "{{ url_for('static', filename='images/f.jpeg') }}"},
        {"name": "Supradyn Daily Multivitamin", "image":  "{{ url_for('static', filename='images/i.jpeg') }}"}
    ],

    "General Nutritional Maintenance": [
        {"name": "Centrum Men Multivitamin", "image": "{{ url_for('static', filename='images/f.jpeg') }}"},
        {"name": "Supradyn Daily Multivitamin", "image":  "{{ url_for('static', filename='images/i.jpeg') }}"},
        {"name": "HealthKart HK Vitals Multivitamin", "image": "{{ url_for('static', filename='images/g.jpeg') }}"}
    ],
    "Heart Health Benefits": [
        {"name": "GNC Mega Men One Daily", "image": "{{ url_for('static', filename='images/a.jpeg') }}"},
        {"name": "Swisse Ultivite Men's Multivitamin", "image": "{{ url_for('static', filename='images/e.jpeg') }}"},
        {"name": "Seven Seas Perfect 7", "image": "{{ url_for('static', filename='images/m.jpeg') }}"}
    ],
    "Balanced Weight Maintenance": [
        {"name": "Liveasy Wellness Multivitamin Multimineral", "image": "{{ url_for('static', filename='images/n.jpeg') }}"},
        {"name": "HealthKart HK Vitals Multivitamin", "image": "{{ url_for('static', filename='images/g.jpeg') }}"}
    ],
    "Weak Immunity": [
        {"name": "Zincovit Tablet", "image": "{{ url_for('static', filename='images/h.jpeg') }}"},
        {"name": "MuscleTech Platinum Multivitamin", "image": "{{ url_for('static', filename='images/o.jpeg') }}"},
        {"name": "Neurobion Forte Vitamin B12 Tablet", "image": "{{ url_for('static', filename='images/s.jpeg') }}"}
    ],
    "Low Focus": [
        {"name": "GNC Mega Men One Daily", "image":"{{ url_for('static', filename='images/a.jpeg') }}"},
        {"name": "Omega-3 Supplements", "image": "{{ url_for('static', filename='images/p.jpeg') }}"},
        {"name": "Swisse Ultivite Men's Multivitamin", "image":"{{ url_for('static', filename='images/e.jpeg') }}"}
    ],
    "Fatigue": [
        {"name": "Becozym C Forte", "image": "{{ url_for('static', filename='images/r.jpeg') }}"},
        {"name": "Neurobion Forte Vitamin B12 Tablet", "image": "{{ url_for('static', filename='images/s.jpeg') }}"},
        {"name": "Swisse Ultivite Women's Multivitamin", "image":"{{ url_for('static', filename='images/e.jpeg') }}"}
    ],
    "Vitamin B12 & Iron Deficiency (Diet Restriction)": [
        {"name": "Neurobion Forte Vitamin B12 Tablet", "image": "{{ url_for('static', filename='images/r.jpeg') }}"},
        {"name": "Shelcal 500mg", "image": "{{ url_for('static', filename='images/t.jpeg') }}"},
        {"name": "Iron Supplement", "image":  "{{ url_for('static', filename='images/.jpeg') }}"},
    ],
    "Moderate Junk Food Intake": [
        {"name": "Digestive Enzymes", "image":"{{ url_for('static', filename='images/q.jpeg') }}"},
        {"name": "Probiotics", "image": "{{ url_for('static', filename='images/u.jpeg') }}"},
        {"name": "Pharmeasy Multivitamin Multimineral", "image": "{{ url_for('static', filename='images/v.jpeg') }}"}
                ],
    "Iron & Vitamin D Deficiency (Low Energy)": [
        {"name": "Shelcal 500mg", "image": "{{ url_for('static', filename='images/t.jpeg') }}"},
        {"name": "Calcimax Forte Plus", "image": "{{ url_for('static', filename='images/w.jpeg') }}"},
        {"name": "Optimum Nutrition Opti-Women","image":  "{{ url_for('static', filename='images/x.jpeg') }}"}
    ]

}
    
    recommended_multivitamins = []
    
    for deficiency in deficiencies:
        if deficiency in deficiency_to_multivitamin:
            recommended_multivitamins.extend(deficiency_to_multivitamin[deficiency])
            print(f"✅ Added recommendations for {deficiency}: {deficiency_to_multivitamin[deficiency]}")

    return render_template("recommendation.html")
    
    return recommended_multivitamins[:4]  # Return only the top 4 recommendations

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
        print("📩 Full Received Data:", data)  # ✅ Debugging

        user_id = session['user_id']
        question_id = data.get('question_id')
        selected_option = data.get('selected_option')
        quiz_category = data.get('quiz_category')  # "mental_health" or "physical_health"
        level = data.get('level')  # Only for physical health

        # ✅ Check for missing fields
        if quiz_category == "physical_health":
            required_fields = ['question_id', 'selected_option', 'quiz_category', 'level']
        else:  # Mental health doesn't have levels
            required_fields = ['question_id', 'selected_option', 'quiz_category', 'score']

        missing_fields = [field for field in required_fields if data.get(field) is None]
        if missing_fields:
            print(f"❌ Error: Missing fields - {missing_fields}")
            return jsonify({"error": f"Incomplete data. Missing: {missing_fields}"}), 400

        # ✅ Separate storage logic
        if quiz_category == "mental_health":
            score = data.get('score', 0)  # Only for mental health
            print(f"📝 Storing (Mental Health): user_id={user_id}, question_id={question_id}, answer={selected_option}, score={score}")

            update_data = {
                "user_id": str(user_id),
                "category": "mental_health",
                "responses": {
                    question_id: {
                        "answer": selected_option,
                        "score": score,
                        "timestamp": datetime.utcnow()
                    }
                }
            }

            # ✅ Update or insert mental health quiz data
            quiz_responses.update_one(
                {"user_id": str(user_id), "category": "mental_health"},
                {"$set": {f"responses.{question_id}": update_data["responses"][question_id]}},
                upsert=True
            )

        elif quiz_category == "physical_health":
            if not level:
                print("❌ Error: Level required for physical health")
                return jsonify({"error": "Level is required for physical health"}), 400

            print(f"📝 Storing (Physical Health): user_id={user_id}, level={level}, question_id={question_id}, answer={selected_option}")

            update_data = {
                "user_id": str(user_id),
                "category": "physical_health",
                "responses": {
                    level: {
                        question_id: {
                            "answer": selected_option,
                            "timestamp": datetime.utcnow()
                        }
                    }
                }
            }

            # ✅ Update or insert physical health quiz data
            quiz_responses.update_one(
                {"user_id": str(user_id), "category": "physical_health"},
                {"$set": {f"responses.{level}.{question_id}": update_data["responses"][level][question_id]}},
                upsert=True
            )

        else:
            print("❌ Error: Invalid quiz_category received")
            return jsonify({"error": "Invalid quiz category"}), 400

        print("✅ Response stored successfully!")
        return jsonify({"message": f"{quiz_category.capitalize()} response stored successfully!"}), 201

    except Exception as e:
        print("🚨 Error in /store_quiz_response:", str(e))
        return jsonify({"error": str(e)}), 500
    
@app.route('/calculate_score', methods=['GET'])
def calculate_score():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401

    user_id = session['user_id']

    # ✅ Fetch user responses from MongoDB
    user_quiz = quiz_responses.find_one({"user_id": str(user_id)})

    if not user_quiz or "mental_health" not in user_quiz:
        return jsonify({"error": "No responses found"}), 404

    total_score = 0
    # ✅ Iterate through mental_health responses and sum scores
    for key, value in user_quiz["mental_health"].items():
        if isinstance(value, dict) and "score" in value:
            total_score += value["score"]  # ✅ Directly sum stored scores

    print("✅ Final Calculated Score:", total_score)  # Debugging

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
    appointments = list(mongo.db.appointments.find({}, {"_id": 0}))  # "_id" exclude kar diya
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


@app.route('/logout')
def logout():
    """Clear the session and log out the user."""
    session.clear()
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(debug=True)