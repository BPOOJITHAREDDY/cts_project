from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
import secrets
import joblib
import numpy as np

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ✅ Load trained ML model
try:
    model = joblib.load("model_crossval_lightgbm.pkl")
except Exception as e:
    print("Error loading model:", e)
    model = None


# ✅ Database connection
def get_mysql_connection():
    return pymysql.connect(
        host='localhost',
        port=3306,
        user='root',
        password='root1234',   # ✅ correct password
        db='predictions',
        cursorclass=pymysql.cursors.DictCursor
    )


# ---------------- ROUTES ---------------- #

@app.route('/')
def index():
    return render_template('index.html')


# ---- LOGIN PAGES ----
@app.route('/patient/login')
def patient_login():
    return render_template('patient_login.html')

@app.route('/admin/login')
def admin_login():
    return render_template('admin_login.html')

@app.route('/management/login')
def management_login():
    return render_template('management_login.html')


# ---- LOGIN HANDLERS ----
@app.route('/management/login', methods=['POST'])
def management_login_post():
    username = request.form['username']
    password = request.form['password']
    
    if username == 'manager' and password == 'password':
        session['user_id'] = 'management_user'
        session['username'] = 'manager'
        session['user_type'] = 'management'
        return redirect(url_for('management_dashboard'))
    else:
        flash('Invalid management credentials')
        return redirect(url_for('management_login'))


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user_type = request.form['user_type']

    # Redirect management login attempts
    if user_type == 'management':
        return redirect(url_for('management_login'))

    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        cursor.execute(
            'SELECT id, username, password_hash, user_type FROM users WHERE username = %s AND user_type = %s',
            (username, user_type)
        )
        user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['user_type'] = user['user_type']

        if user_type == 'patient':
            return redirect(url_for('patient_dashboard'))
        elif user_type == 'admin':
            return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid credentials')
        if user_type == 'patient':
            return redirect(url_for('patient_login'))
        elif user_type == 'admin':
            return redirect(url_for('admin_login'))


# ---- REGISTER ----
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    user_type = request.form['user_type']

    if user_type == 'management':
        flash('Management accounts cannot be registered')
        return redirect(url_for('management_login'))

    conn = get_mysql_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, user_type) VALUES (%s, %s, %s, %s)',
                (username, email, generate_password_hash(password), user_type)
            )
        conn.commit()
        flash('Registration successful! Please login.')
    except pymysql.err.IntegrityError:
        flash('Username or email already exists')
    conn.close()

    if user_type == 'patient':
        return redirect(url_for('patient_login'))
    elif user_type == 'admin':
        return redirect(url_for('admin_login'))


# ---- DASHBOARDS ----
@app.route('/patient/dashboard')
def patient_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'patient':
        return redirect(url_for('patient_login'))
    return render_template('patient_dashboard.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')


@app.route('/management/dashboard')
def management_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'management':
        return redirect(url_for('management_login'))
    
    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        cursor.execute('SELECT COUNT(*) AS count FROM users')
        total_users = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) AS count FROM users WHERE user_type = "admin"')
        admin_count = cursor.fetchone()['count']
        
        cursor.execute('SELECT COUNT(*) AS count FROM users WHERE user_type = "patient"')
        patient_count = cursor.fetchone()['count']
        
        high_risk_count = patient_count  # placeholder
        cursor.execute("SELECT * FROM users ORDER BY created_at DESC LIMIT 4")
        recent_users = cursor.fetchall()
    conn.close()
    
    return render_template(
        'management_dashboard.html',
        users=users,
        admin_count=admin_count,
        patient_count=patient_count,
        high_risk_count=high_risk_count,
        recent_users=recent_users
    )


# ---- ADMIN ROUTES ----
@app.route('/admin/manage_patients')
def manage_patients():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))

    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE user_type='patient'")
        patients = cursor.fetchall()
    conn.close()

    return render_template('manage_patients.html', patients=patients)


@app.route('/admin/reports')
def admin_reports():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    return render_template('admin_reports.html')


@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))

    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        admin = cursor.fetchone()

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        with conn.cursor() as cursor:
            if password.strip() != "":
                hashed_password = generate_password_hash(password)
                cursor.execute("""
                    UPDATE users SET username=%s, email=%s, password_hash=%s WHERE id=%s
                """, (username, email, hashed_password, session['user_id']))
            else:
                cursor.execute("""
                    UPDATE users SET username=%s, email=%s WHERE id=%s
                """, (username, email, session['user_id']))
        conn.commit()

        # Update session username
        session['username'] = username
        flash("✅ Admin settings updated successfully!", "success")
        return redirect(url_for('admin_settings'))

    conn.close()
    return render_template('admin_settings.html', admin=admin)


@app.route('/admin/logout')
def management_logout():
    session.clear()
    return redirect(url_for('management_login'))


# ---- ADMIN: ADD PATIENT RECORD ----
@app.route('/add_record', methods=['GET', 'POST'])
def add_record():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        try:
            patient_id = request.form['patient_id']
            age = request.form['age']
            gender = request.form['gender']
            diagnosis = request.form['diagnosis']
            readmission_risk = request.form['readmission_risk']

            conn = get_mysql_connection()
            with conn.cursor() as cursor:
                cursor.execute(
                    'INSERT INTO patient_data (patient_id, age, gender, diagnosis, readmission_risk) VALUES (%s, %s, %s, %s, %s)',
                    (patient_id, age, gender, diagnosis, readmission_risk)
                )
            conn.commit()
            conn.close()

            flash('✅ Patient record added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash(f'❌ Error adding record: {str(e)}', 'danger')
            return redirect(url_for('add_record'))

    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        cursor.execute('SELECT id, username FROM users WHERE user_type="patient"')
        patients = cursor.fetchall()
    conn.close()

    return render_template('add_record.html', patients=patients)


# ---- PREDICTION (ADMIN ONLY NOW) ----
@app.route('/predict-form')
def predict_form():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect(url_for('admin_login'))
    return render_template('predict.html')


@app.route("/predict", methods=["POST"])
def predict():
    try:
        n_inpatient = int(request.form["n_inpatient"])
        n_lab_procedures = int(request.form["n_lab_procedures"])
        n_emergency = int(request.form["n_emergency"])
        age_cat = request.form["age_cat"]
        medical_specialty = request.form["medical_specialty"]
        med_change = request.form["med_change"]
        diabetes_med = request.form["diabetes_med"]

        categorical_map = {
            "age_cat": {
                "early-middle age": 0,
                "late-middle age": 1,
                "mid-old age": 2,
                "senior-old age": 3,
                "very senior-old": 4,
                "centenarians": 5
            },
            "med_change": {"No": 0, "Yes": 1},
            "diabetes_med": {"No": 0, "Yes": 1},
            "medical_specialty": {
                "Cardiology": 0,
                "Endocrinology": 1,
                "Family/GeneralPractice": 2,
                "InternalMedicine": 3,
                "Nephrology": 4,
                "Neurology": 5,
                "Obstetrics": 6,
                "Orthopedics": 7,
                "Pediatrics": 8,
                "Psychiatry": 9,
                "Surgery": 10,
                "Other": 11
            }
        }

        age_val = categorical_map["age_cat"][age_cat]
        med_change_val = categorical_map["med_change"][med_change]
        diabetes_med_val = categorical_map["diabetes_med"][diabetes_med]
        specialty_val = categorical_map["medical_specialty"].get(medical_specialty, 11)

        features = np.array([[n_inpatient, n_lab_procedures, n_emergency,
                              age_val, specialty_val, med_change_val, diabetes_med_val]])

        prob = model.predict_proba(features)[0][1] if model else 0
        prediction = 1 if prob >= 0.5 else 0

        if prob < 0.3:
            risk_level = "Low"
            recommendation = "Routine discharge. Standard follow-up is sufficient."
        elif 0.3 <= prob < 0.7:
            risk_level = "Medium"
            recommendation = "Schedule follow-up within 7 days and monitor vitals."
        else:
            risk_level = "High"
            recommendation = "Immediate follow-up call, home visit, or special care plan needed."

        result_text = "Patient will be Readmitted" if prediction == 1 else "Patient will NOT be Readmitted"

        return render_template("result.html",
                               prediction=result_text,
                               risk=risk_level,
                               probability=round(prob * 100, 2),
                               recommendation=recommendation)

    except Exception as e:
        return f"Error during prediction: {str(e)} <br><a href='/predict-form'>Go Back</a>"


# ---- LOGOUT ----
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---- USERS LIST ----
@app.route('/users')
def users():
    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
    conn.close()
    return render_template('users.html', users=users)


# ---- TEST MYSQL ----
@app.route('/test-mysql')
def test_mysql():
    try:
        conn = get_mysql_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
        conn.close()
        return f"MySQL connection successful! Version: {version['VERSION()']}"""
    except Exception as e:
        return f"MySQL connection failed: {e}"


@app.route('/hello')
def hello():
    return "Hello, Flask!"


# ---------------- MAIN ---------------- #
if __name__ == '__main__':
    app.run(debug=True)
