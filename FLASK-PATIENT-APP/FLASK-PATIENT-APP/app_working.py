#!/usr/bin/env python3

import pymysql
from flask import Flask, request, redirect, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import random
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'simple_secret_key'



# Database connection
def get_mysql_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='poojitha2005',
        database='hospital_system',
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,  # Disable autocommit for better transaction control
        charset='utf8mb4',
        connect_timeout=60,
        read_timeout=60,
        write_timeout=60
    )

def execute_with_retry(cursor, query, params=None, max_retries=3):
    """Execute database query with retry logic for lock timeout issues"""
    for attempt in range(max_retries):
        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return True
        except pymysql.err.OperationalError as e:
            if e.args[0] == 1205 and attempt < max_retries - 1:  # Lock wait timeout
                import time
                time.sleep(0.5 * (attempt + 1))  # Exponential backoff
                continue
            else:
                raise e
        except Exception as e:
            raise e
    return False

def optimize_database_connection():
    """Optimize database connection settings to prevent lock timeouts"""
    try:
        conn = get_mysql_connection()
        with conn.cursor() as cursor:
            # Set session variables to prevent lock timeouts (execute one by one)
            try:
                cursor.execute("SET SESSION innodb_lock_wait_timeout = 50")
            except Exception:
                pass  # Some MySQL versions don't support this
            
            try:
                cursor.execute("SET SESSION autocommit = 0")
            except Exception:
                pass
            
            try:
                cursor.execute("SET SESSION transaction_isolation = 'READ-COMMITTED'")
            except Exception:
                pass
                
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Warning: Could not optimize database connection: {e}")
        return False

def test_database_connection():
    """Test database connection and basic operations"""
    try:
        conn = get_mysql_connection()
        with conn.cursor() as cursor:
            # Test basic query
            cursor.execute("SELECT 1 as test")
            result = cursor.fetchone()
            if result and result['test'] == 1:
                print("✅ Database connection test successful")
                return True
        conn.close()
        return False
    except Exception as e:
        print(f"❌ Database connection test failed: {e}")
        return False

def find_available_port(start_port=5000, max_attempts=10):
    """Find an available port to run the Flask app"""
    import socket
    
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                print(f"✅ Port {port} is available")
                return port
        except OSError:
            print(f"⚠️  Port {port} is busy")
            continue
    
    print("❌ No available ports found in range")
    return None



@app.route('/')
def index():
    return '''
    <html>
    <head><title>Hospital Readmission Prediction System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .hero-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 100px 0;
        }
        .feature-card {
            transition: transform 0.3s ease;
        }
        .feature-card:hover {
            transform: translateY(-5px);
        }
        .portal-card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
        }
        .portal-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }
    </style>
    </head>
    <body>
        <!-- Hero Section -->
        <div class="hero-section text-center">
            <div class="container">
                <h1 class="display-4 mb-4">
                    <i class="fas fa-heartbeat me-3"></i>
                    Hospital Readmission Prediction System
                </h1>
                <p class="lead mb-5">Advanced AI-powered healthcare management platform for predicting patient readmission risks and improving care outcomes.</p>
                
                <!-- Login Portals -->
                <div class="row justify-content-center">
                    <div class="col-md-4 mb-4">
                        <div class="card portal-card h-100">
                            <div class="card-body text-center p-4">
                                <div class="mb-3">
                                    <i class="fas fa-user-md fa-3x text-primary"></i>
                                </div>
                                <h5 class="card-title text-dark">Admin Portal</h5>
                                <p class="card-text text-muted">Manage patients, add medical records, view reports and predictions</p>
                                <a href="/admin/login" class="btn btn-primary btn-lg w-100">
                                    <i class="fas fa-sign-in-alt me-2"></i>Admin Login
                                </a>
                                <small class="text-muted d-block mt-2">admin / admin123</small>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4 mb-4">
                        <div class="card portal-card h-100">
                            <div class="card-body text-center p-4">
                                <div class="mb-3">
                                    <i class="fas fa-user-injured fa-3x text-success"></i>
                                </div>
                                <h5 class="card-title text-dark">Patient Portal</h5>
                                <p class="card-text text-muted">View your medical reports, readmission risks and treatment history</p>
                                <a href="/patient/login" class="btn btn-success btn-lg w-100">
                                    <i class="fas fa-sign-in-alt me-2"></i>Patient Login
                                </a>
                                <small class="text-muted d-block mt-2">patient / patient123</small>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4 mb-4">
                        <div class="card portal-card h-100">
                            <div class="card-body text-center p-4">
                                <div class="mb-3">
                                    <i class="fas fa-building fa-3x text-dark"></i>
                                </div>
                                <h5 class="card-title text-dark">Management Portal</h5>
                                <p class="card-text text-muted">Analytics, KPIs, system overview and performance metrics</p>
                                <a href="/management/login" class="btn btn-dark btn-lg w-100">
                                    <i class="fas fa-sign-in-alt me-2"></i>Management Login
                                </a>
                                <small class="text-muted d-block mt-2">manager / manager123</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Features Section -->
        <div class="container py-5">
            <div class="row text-center mb-5">
                <div class="col-12">
                    <h2 class="display-5 mb-4">Key Features</h2>
                    <p class="lead text-muted">Comprehensive healthcare management with AI-powered predictions</p>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-4 mb-4">
                    <div class="card feature-card h-100 border-0 shadow-sm">
                        <div class="card-body text-center p-4">
                            <i class="fas fa-brain fa-3x text-warning mb-3"></i>
                            <h5 class="card-title">AI Predictions</h5>
                            <p class="card-text">Advanced machine learning algorithms to predict patient readmission risks with high accuracy.</p>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4 mb-4">
                    <div class="card feature-card h-100 border-0 shadow-sm">
                        <div class="card-body text-center p-4">
                            <i class="fas fa-chart-line fa-3x text-info mb-3"></i>
                            <h5 class="card-title">Real-time Analytics</h5>
                            <p class="card-text">Dynamic dashboards with live data insights, KPIs and performance metrics for better decision making.</p>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4 mb-4">
                    <div class="card feature-card h-100 border-0 shadow-sm">
                        <div class="card-body text-center p-4">
                            <i class="fas fa-shield-alt fa-3x text-danger mb-3"></i>
                            <h5 class="card-title">Secure Access</h5>
                            <p class="card-text">Role-based authentication system ensuring data privacy and secure access for all user types.</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-4">
                    <div class="card feature-card h-100 border-0 shadow-sm">
                        <div class="card-body text-center p-4">
                            <i class="fas fa-database fa-3x text-primary mb-3"></i>
                            <h5 class="card-title">Dynamic Data Management</h5>
                            <p class="card-text">Complete CRUD operations for patient records, medical history, and treatment plans with real-time updates.</p>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6 mb-4">
                    <div class="card feature-card h-100 border-0 shadow-sm">
                        <div class="card-body text-center p-4">
                            <i class="fas fa-file-medical-alt fa-3x text-success mb-3"></i>
                            <h5 class="card-title">Comprehensive Reports</h5>
                            <p class="card-text">Detailed medical reports, risk assessments, and exportable analytics for healthcare professionals.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <footer class="bg-dark text-white py-4 mt-5">
            <div class="container text-center">
                <div class="row">
                    <div class="col-12">
                        <h5><i class="fas fa-hospital me-2"></i>Hospital Readmission Prediction System</h5>
                        <p class="mb-2">Improving patient care through predictive analytics</p>
                        <p class="text-muted mb-0">
                            <small>© 2025 Hospital Management System. All rights reserved.</small>
                        </p>
                    </div>
                </div>
            </div>
        </footer>
    </body>
    </html>
    '''

@app.route('/health')
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected' if test_database_connection() else 'disconnected'
    })

@app.route('/debug/patients')
def debug_patients():
    """Debug endpoint to see what patients exist in the system"""
    try:
        conn = get_mysql_connection()
        try:
            with conn.cursor() as cursor:
                execute_with_retry(cursor, """
                    SELECT id, username, email, user_type, created_at 
                    FROM users 
                    WHERE user_type = 'patient' 
                    ORDER BY created_at DESC 
                    LIMIT 10
                """)
                patients = cursor.fetchall()
        finally:
            conn.close()
        
        return jsonify({
            'status': 'success',
            'patients': patients,
            'count': len(patients),
            'note': 'Default password for all patients is: patient123'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        })

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        
        try:
            conn = get_mysql_connection()
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM users 
                    WHERE (username = %s OR email = %s) AND user_type = 'admin'
                """, (login, login))
                user = cursor.fetchone()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['user_type'] = user['user_type']
                return redirect('/admin/dashboard')
            else:
                error = "Invalid credentials!"
        except Exception as e:
            error = f"Database error: {str(e)}"
    else:
        error = ""
    
    return f'''
    <html>
    <head><title>Admin Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h4>👨‍⚕️ Admin Login</h4>
                        </div>
                        <div class="card-body">
                            {f"<div class='alert alert-danger'>{error}</div>" if error else ""}
                            <form method="POST">
                                <div class="mb-3">
                                    <label class="form-label">Username or Email</label>
                                    <input type="text" name="login" class="form-control" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" name="password" class="form-control" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">Login</button>
                            </form>
                            <div class="mt-3 text-center">
                                <small>Default: admin / admin123</small><br>
                                <a href="/" class="btn btn-link">← Back to Home</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')
    
    return f'''
    <html>
    <head><title>Admin Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <h1 class="text-center mb-4">Admin Dashboard</h1>
            <div class="alert alert-info text-center">
                Welcome, {session.get('username')}! 
                <a href="/logout" class="btn btn-sm btn-outline-danger ms-2">Logout</a>
            </div>
            
            <div class="row">
                <div class="col-md-6 mb-3">
                    <a href="/manage_patients" class="btn btn-primary w-100 py-3">
                        <i class="fas fa-users"></i> Manage Patients
                    </a>
                </div>
                <div class="col-md-6 mb-3">
                    <a href="/add_record" class="btn btn-success w-100 py-3">
                        <i class="fas fa-plus-circle"></i> Add Medical Records
                    </a>
                </div>
                <div class="col-md-6 mb-3">
                    <a href="/admin/reports" class="btn btn-info w-100 py-3">
                        <i class="fas fa-chart-bar"></i> View Reports
                    </a>
                </div>
                <div class="col-md-6 mb-3">
                    <a href="/predict" class="btn btn-warning w-100 py-3">
                        <i class="fas fa-brain"></i> Predict Readmission
                    </a>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/add_record', methods=['GET', 'POST'])
def add_record():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')

    if request.method == 'POST':
        try:
            # Get form data
            patient_email = request.form['patient_email']
            age = request.form['age']
            gender = request.form['gender']
            diagnosis = request.form['diagnosis']
            
            # Debug: Print form data
            print(f"DEBUG: Form data received - Email: {patient_email}, Age: {age}, Gender: {gender}, Diagnosis: {diagnosis}")
            treatment = request.form.get('treatment', '')
            doctor_name = request.form.get('doctor_name', '').strip()  # Use exactly what user enters
            if not doctor_name:  # Only use admin username if field is completely empty
                doctor_name = session.get('username', 'Admin')
            print(f"DEBUG: Doctor name set to: {doctor_name}")
            
            # Additional medical fields with proper validation
            n_inpatient = request.form.get('n_inpatient', '0')
            n_lab_procedures = request.form.get('n_lab_procedures', '0')
            n_emergency = request.form.get('n_emergency', '0')
            medical_specialty = request.form.get('medical_specialty', '')
            age_cat = request.form.get('age_cat', '')
            med_change = request.form.get('med_change', '')
            diabetes_med = request.form.get('diabetes_med', '')
            time_in_hospital = request.form.get('time_in_hospital', '0')
            num_procedures = request.form.get('num_procedures', '0')
            num_medications = request.form.get('num_medications', '0')
            num_diagnoses = request.form.get('num_diagnoses', '0')
            
            # Convert to integers safely
            try:
                n_inpatient = int(n_inpatient) if n_inpatient else 0
                n_lab_procedures = int(n_lab_procedures) if n_lab_procedures else 0
                n_emergency = int(n_emergency) if n_emergency else 0
                time_in_hospital = int(time_in_hospital) if time_in_hospital else 0
                num_procedures = int(num_procedures) if num_procedures else 0
                num_medications = int(num_medications) if num_medications else 0
                num_diagnoses = int(num_diagnoses) if num_diagnoses else 0
            except (ValueError, TypeError):
                n_inpatient = n_lab_procedures = n_emergency = time_in_hospital = 0
                num_procedures = num_medications = num_diagnoses = 0
            
            # Generate a more sophisticated risk score based on multiple factors
            base_risk = random.randint(20, 80)
            
            # Adjust risk based on factors
            if n_inpatient > 5:
                base_risk += 15
            if n_emergency > 3:
                base_risk += 10
            if time_in_hospital > 7:
                base_risk += 12
            if num_medications > 10:
                base_risk += 8
            if num_diagnoses > 5:
                base_risk += 10
            if age_cat in ['elderly', 'very elderly']:
                base_risk += 15
            if medical_specialty in ['Cardiology', 'Neurology', 'Oncology']:
                base_risk += 8
            
            readmission_risk = min(100, max(0, base_risk))
            

            
            doctor_id = session['user_id']

            conn = get_mysql_connection()
            try:
                with conn.cursor() as cursor:
                    # First, try to find existing patient by email
                    execute_with_retry(cursor, "SELECT id FROM users WHERE email = %s AND user_type = 'patient'", (patient_email,))
                    patient_record = cursor.fetchone()
                
                    if patient_record:
                        # Patient exists, use their ID
                        patient_id = patient_record['id']
                    else:
                        # Patient doesn't exist, create a new patient record
                        username = patient_email.split('@')[0]  # Use part before @ as username
                        default_password = generate_password_hash('patient123')  # Default password
                        
                        execute_with_retry(cursor, """
                            INSERT INTO users (username, email, password, user_type) 
                            VALUES (%s, %s, %s, 'patient')
                        """, (username, patient_email, default_password))
                        patient_id = cursor.lastrowid
                    
                    print(f"DEBUG: About to insert - Patient ID: {patient_id}, Doctor ID: {doctor_id}, Doctor Name: '{doctor_name}'")
                    print(f"DEBUG: Values - Age: {age}, Gender: {gender}, Risk: {readmission_risk}")
                    print(f"DEBUG: Session username: {session.get('username')}")
                    execute_with_retry(cursor, """
                        INSERT INTO patient_data 
                        (patient_id, age, gender, diagnosis, treatment, doctor_id, doctor_name, readmission_risk,
                         n_inpatient, n_lab_procedures, n_emergency, medical_specialty, age_cat, 
                         med_change, diabetes_med, time_in_hospital, num_procedures, num_medications, num_diagnoses) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (patient_id, age, gender, diagnosis, treatment, doctor_id, doctor_name, readmission_risk,
                          n_inpatient, n_lab_procedures, n_emergency, medical_specialty, age_cat,
                          med_change, diabetes_med, time_in_hospital, num_procedures, num_medications, num_diagnoses))
                
                conn.commit()
            except Exception as e:
                try:
                    conn.rollback()
                except Exception:
                    pass  # Ignore rollback errors
                error = str(e)
                print(f"DEBUG: Error in add_record: {error}")
                print(f"DEBUG: Form data - Email: {patient_email}, Age: {age}, Gender: {gender}")
                return '''
                <html>
                <head><title>Error</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body class="bg-light">
                    <div class="container mt-5">
                        <div class="alert alert-danger text-center">
                            <h4>❌ Error Adding Medical Record</h4>
                            <p><strong>Error:</strong> Database or form validation error occurred</p>
                            <a href="/add_record" class="btn btn-primary">Try Again</a>
                            <a href="/admin/dashboard" class="btn btn-secondary">Back to Dashboard</a>
                        </div>
                    </div>
                </body>
                </html>
                '''
            finally:
                try:
                    if conn and hasattr(conn, 'open') and conn.open:
                        conn.close()
                except Exception:
                    pass  # Ignore errors when closing connection

            return f'''
            <html>
            <head><title>Success</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-success text-center">
                        <h4>✅ Patient Record Added Successfully!</h4>
                        <p><strong>Patient Email:</strong> {patient_email}</p>
                        <p><strong>Doctor:</strong> Dr. {doctor_name}</p>
                        <p><small class="text-muted">Note: If this was a new patient, they can now login with email and password 'patient123'</small></p>
                        <a href="/admin/dashboard" class="btn btn-primary">Back to Dashboard</a>
                        <a href="/add_record" class="btn btn-success">Add Another Record</a>
                    </div>
                </div>
            </body>
            </html>
            '''
        except Exception as e:
            error = str(e)
    else:
        error = ""

    return f'''
    <html>
    <head><title>Add Medical Record</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .form-section {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .form-section h6 {{
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 8px;
            margin-bottom: 20px;
        }}
        .auto-fill-info {{
            background: #e3f2fd;
            border: 1px solid #2196f3;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 15px;
        }}
    </style>
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/admin/dashboard">
                    <i class="fas fa-user-md"></i> Admin Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="row justify-content-center">
                <div class="col-md-10">
                    <div class="card shadow">
                        <div class="card-header bg-success text-white">
                            <h4><i class="fas fa-plus-circle"></i> Add Medical Record</h4>
                            <small>Comprehensive patient assessment with auto-fill and prediction capabilities</small>
                        </div>
                        <div class="card-body">
                            {f"<div class='alert alert-danger'>{error}</div>" if error else ""}
                            
                            <!-- Auto-fill Information -->
                            <div class="auto-fill-info">
                                <i class="fas fa-info-circle me-2"></i>
                                <strong>Auto-fill Feature:</strong> Enter a patient email to automatically populate existing data and get visit statistics.
                            </div>
                            
                            <form method="POST" id="patientForm">
                                <!-- Patient Information Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-user me-2"></i>Patient Information</h6>
                                <div class="row">
                                                            <div class="col-md-6 mb-3">
                            <label class="form-label">Patient Email *</label>
                                            <input type="email" name="patient_email" id="patient_email" class="form-control" required 
                                                   placeholder="Enter patient email for auto-fill">
                            <small class="form-text text-muted">If patient doesn't exist, a new account will be created automatically</small>
                        </div>
                                        <div class="col-md-3 mb-3">
                                        <label class="form-label">Age *</label>
                                            <input type="number" name="age" id="age" class="form-control" min="1" max="120" required>
                                    </div>
                                        <div class="col-md-3 mb-3">
                                        <label class="form-label">Gender *</label>
                                            <select name="gender" id="gender" class="form-control" required>
                                            <option value="">Select Gender</option>
                                            <option value="Male">Male</option>
                                            <option value="Female">Female</option>
                                            <option value="Other">Other</option>
                                        </select>
                                    </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Age Category</label>
                                            <select name="age_cat" id="age_cat" class="form-control">
                                                <option value="">Select Age Category</option>
                                                <option value="young">Young (18-30)</option>
                                                <option value="early-middle">Early Middle Age (31-45)</option>
                                                <option value="middle">Middle Age (46-60)</option>
                                                <option value="elderly">Elderly (61-75)</option>
                                                <option value="very elderly">Very Elderly (76+)</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Medical Specialty</label>
                                            <select name="medical_specialty" id="medical_specialty" class="form-control">
                                                <option value="">Select Specialty</option>
                                                <option value="Cardiology">Cardiology</option>
                                                <option value="Neurology">Neurology</option>
                                                <option value="Oncology">Oncology</option>
                                                <option value="Orthopedics">Orthopedics</option>
                                                <option value="General Medicine">General Medicine</option>
                                                <option value="Surgery">Surgery</option>
                                                <option value="Pediatrics">Pediatrics</option>
                                                <option value="Emergency Medicine">Emergency Medicine</option>
                                                <option value="Internal Medicine">Internal Medicine</option>
                                                <option value="Other">Other</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Doctor Name *</label>
                                            <input type="text" name="doctor_name" id="doctor_name" class="form-control" required 
                                                   placeholder="Enter doctor name (e.g., Dr. Sam)">
                                            <small class="form-text text-muted">This will appear in patient reports</small>
                                        </div>
                                    </div>
                                </div>

                                <!-- Medical Information Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-stethoscope me-2"></i>Medical Information</h6>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                    <label class="form-label">Primary Diagnosis *</label>
                                            <textarea name="diagnosis" id="diagnosis" class="form-control" rows="3" required 
                                                      placeholder="Enter primary diagnosis..."></textarea>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Number of Diagnoses</label>
                                            <input type="number" name="num_diagnoses" id="num_diagnoses" class="form-control" min="1" max="20" 
                                                   placeholder="Total diagnoses count">
                                        </div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Treatment Plan</label>
                                        <textarea name="treatment" id="treatment" class="form-control" rows="3" 
                                                  placeholder="Describe treatment plan, medications, procedures..."></textarea>
                                </div>
                                </div>

                                <!-- Visit Statistics Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-chart-bar me-2"></i>Visit Statistics</h6>
                                    <div class="row">
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Inpatient Visits</label>
                                            <input type="number" name="n_inpatient" id="n_inpatient" class="form-control" min="0" max="50" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Lab Procedures</label>
                                            <input type="number" name="n_lab_procedures" id="n_lab_procedures" class="form-control" min="0" max="100" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Emergency Visits</label>
                                            <input type="number" name="n_emergency" id="n_emergency" class="form-control" min="0" max="30" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Time in Hospital (Days)</label>
                                            <input type="number" name="time_in_hospital" id="time_in_hospital" class="form-control" min="1" max="30" 
                                                   placeholder="0">
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Number of Procedures</label>
                                            <input type="number" name="num_procedures" id="num_procedures" class="form-control" min="0" max="20" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Number of Medications</label>
                                            <input type="number" name="num_medications" id="num_medications" class="form-control" min="0" max="30" 
                                                   placeholder="0">
                                        </div>
                                    </div>
                                </div>

                                <!-- Medication Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-pills me-2"></i>Medication Information</h6>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Medication Change</label>
                                            <select name="med_change" id="med_change" class="form-control">
                                                <option value="">Select Option</option>
                                                <option value="Yes">Yes</option>
                                                <option value="No">No</option>
                                                <option value="Unknown">Unknown</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Diabetes Medication</label>
                                            <select name="diabetes_med" id="diabetes_med" class="form-control">
                                                <option value="">Select Option</option>
                                                <option value="Yes">Yes</option>
                                                <option value="No">No</option>
                                                <option value="Unknown">Unknown</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>

                                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                    <a href="/admin/dashboard" class="btn btn-secondary me-md-2">Cancel</a>
                                    <button type="submit" class="btn btn-success btn-lg">
                                        <i class="fas fa-plus-circle me-1"></i>Add Medical Record
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
        // Auto-fill functionality
        document.getElementById('patient_email').addEventListener('blur', function() {{
            const email = this.value;
            if (email) {{
                // Fetch patient data from database
                fetch(`/api/patient_data/${{email}}`)
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success && data.patient_data) {{
                            // Auto-fill form fields
                            if (data.patient_data.age) document.getElementById('age').value = data.patient_data.age;
                            if (data.patient_data.gender) document.getElementById('gender').value = data.patient_data.gender;
                            if (data.patient_data.age_cat) document.getElementById('age_cat').value = data.patient_data.age_cat;
                            if (data.patient_data.medical_specialty) document.getElementById('medical_specialty').value = data.patient_data.medical_specialty;
                            if (data.patient_data.diagnosis) document.getElementById('diagnosis').value = data.patient_data.diagnosis;
                            if (data.patient_data.treatment) document.getElementById('treatment').value = data.patient_data.treatment;
                            if (data.patient_data.n_inpatient) document.getElementById('n_inpatient').value = data.patient_data.n_inpatient;
                            if (data.patient_data.n_lab_procedures) document.getElementById('n_lab_procedures').value = data.patient_data.n_lab_procedures;
                            if (data.patient_data.n_emergency) document.getElementById('n_emergency').value = data.patient_data.n_emergency;
                            if (data.patient_data.time_in_hospital) document.getElementById('time_in_hospital').value = data.patient_data.time_in_hospital;
                            if (data.patient_data.num_procedures) document.getElementById('num_procedures').value = data.patient_data.num_procedures;
                            if (data.patient_data.num_medications) document.getElementById('num_medications').value = data.patient_data.num_medications;
                            if (data.patient_data.num_diagnoses) document.getElementById('num_diagnoses').value = data.patient_data.num_diagnoses;
                            if (data.patient_data.med_change) document.getElementById('med_change').value = data.patient_data.med_change;
                            if (data.patient_data.diabetes_med) document.getElementById('diabetes_med').value = data.patient_data.diabetes_med;
                            if (data.patient_data.doctor_name) document.getElementById('doctor_name').value = data.patient_data.doctor_name;
                            
                            // Show success message
                            showAutoFillMessage('Patient data auto-filled successfully!', 'success');
                        }} else {{
                            showAutoFillMessage('No existing patient data found. New patient will be created.', 'info');
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error:', error);
                        showAutoFillMessage('Error fetching patient data. Please check the email.', 'warning');
                    }});
            }}
        }});

        function showAutoFillMessage(message, type) {{
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${{type}} alert-dismissible fade show`;
            alertDiv.innerHTML = `
                ${{message}}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            const form = document.getElementById('patientForm');
            form.insertBefore(alertDiv, form.firstChild);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {{
                if (alertDiv.parentNode) {{
                    alertDiv.remove();
                }}
            }}, 5000);
        }}
        </script>
    </body>
    </html>
    '''

@app.route('/manage_patients')
def manage_patients():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')
    
    # Get all patients and their data
    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.created_at,
                   COUNT(pd.id) as total_records,
                   AVG(pd.readmission_risk) as avg_risk,
                   GROUP_CONCAT(DISTINCT pd.doctor_name SEPARATOR ', ') as doctors
            FROM users u 
            LEFT JOIN patient_data pd ON u.id = pd.patient_id 
            WHERE u.user_type = 'patient' 
            GROUP BY u.id 
            ORDER BY u.created_at DESC
        """)
        patients = cursor.fetchall()
    conn.close()
    
    patients_html = ""
    if patients:
        for patient in patients:
            avg_risk = patient['avg_risk'] or 0
            risk_color = "text-danger" if avg_risk >= 70 else "text-warning" if avg_risk >= 50 else "text-success"
            patients_html += f'''
            <tr>
                <td>{patient['id']}</td>
                <td>{patient['username']}</td>
                <td>{patient['email']}</td>
                <td>{patient['doctors'] or 'No doctor assigned'}</td>
                <td>{patient['total_records']}</td>
                <td class="{risk_color}">{avg_risk:.1f}%</td>
                <td>{patient['created_at'].strftime('%Y-%m-%d') if patient.get('created_at') else 'Unknown'}</td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="viewPatient({patient['id']})">
                        <i class="fas fa-eye"></i> View
                    </button>
                    <button class="btn btn-sm btn-warning" onclick="editPatient({patient['id']})">
                        <i class="fas fa-edit"></i> Edit
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deletePatient({patient['id']})">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </td>
            </tr>
            '''
    else:
        patients_html = '''
        <tr>
            <td colspan="8" class="text-center py-4">
                <i class="fas fa-users fa-2x text-muted mb-2"></i>
                <p class="text-muted">No patients found</p>
            </td>
        </tr>
        '''
    
    return f'''
    <html>
    <head><title>Manage Patients</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/admin/dashboard">
                    <i class="fas fa-user-md"></i> Admin Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="row">
                <div class="col-12">
                    <div class="card shadow-sm">
                        <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                            <h5 class="card-title mb-0">
                                <i class="fas fa-users me-2"></i>
                                Manage Patients
                            </h5>
                            <div>
                                <a href="/admin/dashboard" class="btn btn-secondary me-2">
                                    <i class="fas fa-arrow-left me-1"></i>Back to Dashboard
                                </a>
                                <button class="btn btn-success" onclick="addPatient()">
                                    <i class="fas fa-plus"></i> Add New Patient
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped table-hover">
                                    <thead class="table-dark">
                                        <tr>
                                            <th>ID</th>
                                            <th>Username</th>
                                            <th>Email</th>
                                            <th>Doctors</th>
                                            <th>Records</th>
                                            <th>Avg Risk</th>
                                            <th>Joined</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {patients_html}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        <div class="card-footer text-center">
                            <a href="/admin/dashboard" class="btn btn-primary">
                                <i class="fas fa-arrow-left me-1"></i>Back to Admin Dashboard
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            function viewPatient(id) {{
                window.location.href = '/view_patient/' + id;
            }}
            
            function editPatient(id) {{
                window.location.href = '/edit_patient/' + id;
            }}
            
            function deletePatient(id) {{
                if (confirm('Are you sure you want to delete this patient?\\n\\nThis action cannot be undone.')) {{
                    window.location.href = '/delete_patient/' + id;
                }}
            }}
            
            function addPatient() {{
                window.location.href = '/add_patient';
            }}
        </script>
    </body>
    </html>
    '''

@app.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')
    
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form['username']
            email = request.form['email']
            first_name = request.form.get('first_name', '')
            last_name = request.form.get('last_name', '')
            password = request.form.get('password', 'patient123')
            
            # Hash password
            hashed_password = generate_password_hash(password)
            
            conn = get_mysql_connection()
            try:
                with conn.cursor() as cursor:
                    # Check if username or email already exists
                    execute_with_retry(cursor, "SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
                    existing_user = cursor.fetchone()
                    
                    if existing_user:
                        raise Exception("Username or email already exists!")
                    
                    # Insert new patient
                    execute_with_retry(cursor, """
                        INSERT INTO users (username, email, password, user_type) 
                        VALUES (%s, %s, %s, 'patient')
                    """, (username, email, hashed_password))
                
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                conn.close()
            
            return f'''
            <html>
            <head><title>Success</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-success text-center">
                        <h4>✅ Patient Added Successfully!</h4>
                        <p><strong>Username:</strong> {username}</p>
                        <p><strong>Email:</strong> {email}</p>
                        <p><strong>Password:</strong> {password}</p>
                        <p><small class="text-muted">Patient can now login with these credentials</small></p>
                        <a href="/manage_patients" class="btn btn-primary">Back to Manage Patients</a>
                        <a href="/add_patient" class="btn btn-success">Add Another Patient</a>
                    </div>
                </div>
            </body>
            </html>
            '''
        except Exception as e:
            error = str(e)
    else:
        error = ""
    
    return f'''
    <html>
    <head><title>Add New Patient</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/admin/dashboard">
                    <i class="fas fa-user-md"></i> Admin Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card shadow-sm">
                        <div class="card-header bg-success text-white">
                            <h4><i class="fas fa-user-plus me-2"></i>Add New Patient</h4>
                        </div>
                        <div class="card-body">
                            {f"<div class='alert alert-danger'>{error}</div>" if error else ""}
                            <form method="POST">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Username *</label>
                                        <input type="text" name="username" class="form-control" required placeholder="Enter username">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Email *</label>
                                        <input type="email" name="email" class="form-control" required placeholder="Enter email address">
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">First Name</label>
                                        <input type="text" name="first_name" class="form-control" placeholder="Enter first name">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Last Name</label>
                                        <input type="text" name="last_name" class="form-control" placeholder="Enter last name">
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="text" name="password" class="form-control" value="patient123" placeholder="Enter password">
                                    <small class="form-text text-muted">Default password is 'patient123'. Patient can change this later.</small>
                                </div>
                                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                    <a href="/manage_patients" class="btn btn-secondary me-md-2">Cancel</a>
                                    <button type="submit" class="btn btn-success">
                                        <i class="fas fa-user-plus me-1"></i>Add Patient
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/view_patient/<int:patient_id>')
def view_patient(patient_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')
    
    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        # Get patient info
        cursor.execute("SELECT * FROM users WHERE id = %s AND user_type = 'patient'", (patient_id,))
        patient = cursor.fetchone()
        
        if not patient:
            conn.close()
            return f'''
            <html>
            <head><title>Patient Not Found</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-danger text-center">
                        <h4>Patient Not Found</h4>
                        <a href="/manage_patients" class="btn btn-primary">Back to Manage Patients</a>
                    </div>
                </div>
            </body>
            </html>
            '''
        
        # Get patient's medical records
        cursor.execute("""
            SELECT pd.*, u.username as doctor_name 
            FROM patient_data pd 
            LEFT JOIN users u ON pd.doctor_id = u.id 
            WHERE pd.patient_id = %s 
            ORDER BY pd.created_at DESC
        """, (patient_id,))
        medical_records = cursor.fetchall()
    conn.close()
    
    records_html = ""
    if medical_records:
        for record in medical_records:
            risk_color = "text-danger" if record['readmission_risk'] >= 70 else "text-warning" if record['readmission_risk'] >= 50 else "text-success"
            records_html += f'''
            <div class="card mb-3">
                <div class="card-header d-flex justify-content-between">
                    <strong>{record['diagnosis'] or 'Medical Report'}</strong>
                    <span class="badge bg-secondary">Risk: {record['readmission_risk']}%</span>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>Age:</strong> {record['age']}</p>
                            <p><strong>Gender:</strong> {record['gender']}</p>
                            <p><strong>Doctor:</strong> Dr. {record['doctor_name'] or 'Unknown'}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong>Treatment:</strong> {record['treatment'] or 'Not specified'}</p>
                            <p><strong>Date:</strong> {record['created_at'].strftime('%Y-%m-%d') if record.get('created_at') else 'Unknown'}</p>
                            <p><strong>Risk:</strong> <span class="{risk_color}">{record['readmission_risk']}%</span></p>
                        </div>
                    </div>
                </div>
            </div>
            '''
    else:
        records_html = '''
        <div class="text-center py-5">
            <i class="fas fa-file-medical fa-3x text-muted mb-3"></i>
            <h5>No medical records found</h5>
            <p class="text-muted">This patient has no medical records yet.</p>
        </div>
        '''
    
    return f'''
    <html>
    <head><title>View Patient</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/admin/dashboard">
                    <i class="fas fa-user-md"></i> Admin Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="row">
                <div class="col-12">
                    <div class="card shadow-sm mb-4">
                        <div class="card-header bg-info text-white">
                            <h5 class="card-title mb-0">
                                <i class="fas fa-user me-2"></i>
                                Patient Information
                            </h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <p><strong>ID:</strong> {patient['id']}</p>
                                    <p><strong>Username:</strong> {patient['username']}</p>
                                    <p><strong>Email:</strong> {patient['email']}</p>
                                </div>
                                <div class="col-md-6">
                                    <p><strong>User Type:</strong> {patient['user_type'].title()}</p>
                                    <p><strong>Joined:</strong> {patient['created_at'].strftime('%Y-%m-%d') if patient.get('created_at') else 'Unknown'}</p>
                                </div>
                            </div>
                            <div class="mt-3">
                                <a href="/edit_patient/{patient['id']}" class="btn btn-warning me-2">
                                    <i class="fas fa-edit"></i> Edit Patient
                                </a>
                                <a href="/add_record_for_patient/{patient['id']}" class="btn btn-success me-2">
                                    <i class="fas fa-plus"></i> Add Medical Record
                                </a>
                                <a href="/manage_patients" class="btn btn-secondary">
                                    <i class="fas fa-arrow-left"></i> Back to Manage Patients
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card shadow-sm">
                        <div class="card-header bg-primary text-white">
                            <h5 class="card-title mb-0">
                                <i class="fas fa-file-medical me-2"></i>
                                Medical Records
                            </h5>
                        </div>
                        <div class="card-body">
                            {records_html}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/edit_patient/<int:patient_id>', methods=['GET', 'POST'])
def edit_patient(patient_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')
    
    conn = get_mysql_connection()
    
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form['username']
            email = request.form['email']
            
            with conn.cursor() as cursor:
                # Check if username or email already exists (excluding current patient)
                cursor.execute("""
                    SELECT id FROM users 
                    WHERE (username = %s OR email = %s) AND id != %s
                """, (username, email, patient_id))
                existing_user = cursor.fetchone()
                
                if existing_user:
                    raise Exception("Username or email already exists!")
                
                # Update patient
                cursor.execute("""
                    UPDATE users 
                    SET username = %s, email = %s 
                    WHERE id = %s AND user_type = 'patient'
                """, (username, email, patient_id))
            conn.commit()
            conn.close()
            
            return f'''
            <html>
            <head><title>Success</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-success text-center">
                        <h4>✅ Patient Updated Successfully!</h4>
                        <p><strong>Username:</strong> {username}</p>
                        <p><strong>Email:</strong> {email}</p>
                        <a href="/view_patient/{patient_id}" class="btn btn-primary">View Patient</a>
                        <a href="/manage_patients" class="btn btn-secondary">Back to Manage Patients</a>
                    </div>
                </div>
            </body>
            </html>
            '''
        except Exception as e:
            error = str(e)
    else:
        error = ""
    
    # Get current patient data
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s AND user_type = 'patient'", (patient_id,))
        patient = cursor.fetchone()
    conn.close()
    
    if not patient:
        return redirect('/manage_patients')
    
    return f'''
    <html>
    <head><title>Edit Patient</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/admin/dashboard">
                    <i class="fas fa-user-md"></i> Admin Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card shadow-sm">
                        <div class="card-header bg-warning text-white">
                            <h4><i class="fas fa-user-edit me-2"></i>Edit Patient</h4>
                        </div>
                        <div class="card-body">
                            {f"<div class='alert alert-danger'>{error}</div>" if error else ""}
                            <form method="POST">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Username *</label>
                                        <input type="text" name="username" class="form-control" required value="{patient['username']}">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Email *</label>
                                        <input type="email" name="email" class="form-control" required value="{patient['email']}">
                                    </div>
                                </div>
                                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                    <a href="/view_patient/{patient_id}" class="btn btn-secondary me-md-2">Cancel</a>
                                    <button type="submit" class="btn btn-warning">
                                        <i class="fas fa-save me-1"></i>Update Patient
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/delete_patient/<int:patient_id>')
def delete_patient(patient_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')
    
    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        # Get patient info first
        cursor.execute("SELECT username FROM users WHERE id = %s AND user_type = 'patient'", (patient_id,))
        patient = cursor.fetchone()
        
        if not patient:
            conn.close()
            return redirect('/manage_patients')
        
        # Delete patient's medical records first (foreign key constraint)
        cursor.execute("DELETE FROM patient_data WHERE patient_id = %s", (patient_id,))
        
        # Delete the patient
        cursor.execute("DELETE FROM users WHERE id = %s AND user_type = 'patient'", (patient_id,))
    
    conn.commit()
    conn.close()
    
    return f'''
    <html>
    <head><title>Patient Deleted</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="alert alert-success text-center">
                <h4>✅ Patient Deleted Successfully!</h4>
                <p>Patient <strong>{patient['username']}</strong> and all their medical records have been removed.</p>
                <a href="/manage_patients" class="btn btn-primary">Back to Manage Patients</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/add_record_for_patient/<int:patient_id>', methods=['GET', 'POST'])
def add_record_for_patient(patient_id):
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')
    
    conn = get_mysql_connection()
    
    # Get patient info
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = %s AND user_type = 'patient'", (patient_id,))
        patient = cursor.fetchone()
    
    if not patient:
        conn.close()
        return redirect('/manage_patients')
    
    if request.method == 'POST':
        try:
            # Get form data
            age = request.form['age']
            gender = request.form['gender']
            diagnosis = request.form['diagnosis']
            treatment = request.form.get('treatment', '')
            doctor_name = request.form.get('doctor_name', '').strip()  # Use exactly what user enters
            if not doctor_name:  # Only use admin username if field is completely empty
                doctor_name = session.get('username', 'Admin')
            
            # Additional medical fields with proper validation
            n_inpatient = request.form.get('n_inpatient', '0')
            n_lab_procedures = request.form.get('n_lab_procedures', '0')
            n_emergency = request.form.get('n_emergency', '0')
            medical_specialty = request.form.get('medical_specialty', '')
            age_cat = request.form.get('age_cat', '')
            med_change = request.form.get('med_change', '')
            diabetes_med = request.form.get('diabetes_med', '')
            time_in_hospital = request.form.get('time_in_hospital', '0')
            num_procedures = request.form.get('num_procedures', '0')
            num_medications = request.form.get('num_medications', '0')
            num_diagnoses = request.form.get('num_diagnoses', '0')
            
            # Convert to integers safely
            try:
                n_inpatient = int(n_inpatient) if n_inpatient else 0
                n_lab_procedures = int(n_lab_procedures) if n_lab_procedures else 0
                n_emergency = int(n_emergency) if n_emergency else 0
                time_in_hospital = int(time_in_hospital) if time_in_hospital else 0
                num_procedures = int(num_procedures) if num_procedures else 0
                num_medications = int(num_medications) if num_medications else 0
                num_diagnoses = int(num_diagnoses) if num_diagnoses else 0
            except (ValueError, TypeError):
                n_inpatient = n_lab_procedures = n_emergency = time_in_hospital = 0
                num_procedures = num_medications = num_diagnoses = 0
            
            # Generate a more sophisticated risk score based on multiple factors
            base_risk = random.randint(20, 80)
            
            # Adjust risk based on factors
            if n_inpatient > 5:
                base_risk += 15
            if n_emergency > 3:
                base_risk += 10
            if time_in_hospital > 7:
                base_risk += 12
            if num_medications > 10:
                base_risk += 8
            if num_diagnoses > 5:
                base_risk += 10
            if age_cat in ['elderly', 'very elderly']:
                base_risk += 15
            if medical_specialty in ['Cardiology', 'Neurology', 'Oncology']:
                base_risk += 8
            
            readmission_risk = min(100, max(0, base_risk))
            

            
            doctor_id = session['user_id']

            conn = get_mysql_connection()
            try:
                with conn.cursor() as cursor:
                    execute_with_retry(cursor, """
                    INSERT INTO patient_data 
                        (patient_id, age, gender, diagnosis, treatment, doctor_id, doctor_name, readmission_risk,
                         n_inpatient, n_lab_procedures, n_emergency, medical_specialty, age_cat, 
                         med_change, diabetes_med, time_in_hospital, num_procedures, num_medications, num_diagnoses) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (patient_id, age, gender, diagnosis, treatment, doctor_id, doctor_name, readmission_risk,
                          n_inpatient, n_lab_procedures, n_emergency, medical_specialty, age_cat,
                          med_change, diabetes_med, time_in_hospital, num_procedures, num_medications, num_diagnoses))
                
                conn.commit()
            except Exception as e:
                try:
                    conn.rollback()
                except Exception:
                    pass  # Ignore rollback errors
                error_msg = str(e)
                print(f"DEBUG: Error in add_record_for_patient: {error_msg}")
                print(f"DEBUG: Patient ID: {patient_id}")
                print(f"DEBUG: Form data - Age: {age}, Gender: {gender}, Diagnosis: {diagnosis}")
                return '''
                <html>
                <head><title>Error</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                </head>
                <body class="bg-light">
                    <div class="container mt-5">
                        <div class="alert alert-danger text-center">
                            <h4>❌ Error Adding Medical Record</h4>
                            <p><strong>Error:</strong> Database or form validation error occurred</p>
                            <a href="/admin/dashboard" class="btn btn-primary">Back to Dashboard</a>
                            <a href="/manage_patients" class="btn btn-secondary">Manage Patients</a>
                        </div>
                    </div>
                </body>
                </html>
                '''
            finally:
                try:
                    if conn and hasattr(conn, 'open') and conn.open:
                        conn.close()
                except Exception:
                    pass  # Ignore errors when closing connection

            return f'''
            <html>
            <head><title>Success</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="alert alert-success text-center">
                        <h4>✅ Medical Record Added Successfully!</h4>
                        <p><strong>Patient:</strong> {patient['username']} ({patient['email']})</p>
                        <p><strong>Diagnosis:</strong> {diagnosis}</p>
                        <p><strong>Readmission Risk:</strong> {readmission_risk}%</p>
                        
                        <a href="/view_patient/{patient_id}" class="btn btn-primary">View Patient</a>
                        <a href="/add_record_for_patient/{patient_id}" class="btn btn-success">Add Another Record</a>
                    </div>
                </div>
            </body>
            </html>
            '''
        except Exception as e:
            error = str(e)
    else:
        error = ""
    
    return f'''
    <html>
    <head><title>Add Medical Record</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .form-section {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .form-section h6 {{
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 8px;
            margin-bottom: 20px;
        }}
        .auto-fill-info {{
            background: #e3f2fd;
            border: 1px solid #2196f3;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 15px;
        }}
    </style>
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/admin/dashboard">
                    <i class="fas fa-user-md"></i> Admin Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="row justify-content-center">
                <div class="col-md-10">
                    <div class="card shadow-sm">
                        <div class="card-header bg-success text-white">
                            <h4><i class="fas fa-plus-circle me-2"></i>Add Medical Record for {patient['username']}</h4>
                            <small>Patient Email: {patient['email']}</small>
                        </div>
                        <div class="card-body">
                            {f"<div class='alert alert-danger'>{error}</div>" if error else ""}
                            <!-- Auto-fill Information -->
                            <div class="auto-fill-info">
                                <i class="fas fa-info-circle me-2"></i>
                                <strong>Patient Data:</strong> This form will be pre-filled with existing patient information when available.
                            </div>
                            
                            <form method="POST" id="patientForm">
                                <!-- Patient Information Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-user me-2"></i>Patient Information</h6>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Age *</label>
                                            <input type="number" name="age" id="age" class="form-control" min="1" max="120" required>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Gender *</label>
                                            <select name="gender" id="gender" class="form-control" required>
                                            <option value="">Select Gender</option>
                                            <option value="Male">Male</option>
                                            <option value="Female">Female</option>
                                                <option value="Other">Other</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Age Category</label>
                                            <select name="age_cat" id="age_cat" class="form-control">
                                                <option value="">Select Age Category</option>
                                                <option value="young">Young (18-30)</option>
                                                <option value="early-middle">Early Middle Age (31-45)</option>
                                                <option value="middle">Middle Age (46-60)</option>
                                                <option value="elderly">Elderly (61-75)</option>
                                                <option value="very elderly">Very Elderly (76+)</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Medical Specialty</label>
                                            <select name="medical_specialty" id="medical_specialty" class="form-control">
                                                <option value="">Select Specialty</option>
                                                <option value="Cardiology">Cardiology</option>
                                                <option value="Neurology">Neurology</option>
                                                <option value="Oncology">Oncology</option>
                                                <option value="Orthopedics">Orthopedics</option>
                                                <option value="General Medicine">General Medicine</option>
                                                <option value="Surgery">Surgery</option>
                                                <option value="Pediatrics">Pediatrics</option>
                                                <option value="Emergency Medicine">Emergency Medicine</option>
                                                <option value="Internal Medicine">Internal Medicine</option>
                                                <option value="Other">Other</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Doctor Name</label>
                                            <input type="text" name="doctor_name" id="doctor_name" class="form-control" placeholder="Dr. Smith">
                                    </div>
                                    </div>
                                </div>

                                <!-- Medical Information Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-stethoscope me-2"></i>Medical Information</h6>
                                    <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label class="form-label">Primary Diagnosis *</label>
                                            <textarea name="diagnosis" id="diagnosis" class="form-control" rows="3" required 
                                                      placeholder="Enter primary diagnosis..."></textarea>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Number of Diagnoses</label>
                                            <input type="number" name="num_diagnoses" id="num_diagnoses" class="form-control" min="1" max="20" 
                                                   placeholder="Total diagnoses count">
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Treatment Plan</label>
                                        <textarea name="treatment" id="treatment" class="form-control" rows="3" 
                                                  placeholder="Describe treatment plan, medications, procedures..."></textarea>
                                </div>
                                </div>

                                <!-- Visit Statistics Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-chart-bar me-2"></i>Visit Statistics</h6>
                                    <div class="row">
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Inpatient Visits</label>
                                            <input type="number" name="n_inpatient" id="n_inpatient" class="form-control" min="0" max="50" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Lab Procedures</label>
                                            <input type="number" name="n_lab_procedures" id="n_lab_procedures" class="form-control" min="0" max="100" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Emergency Visits</label>
                                            <input type="number" name="n_emergency" id="n_emergency" class="form-control" min="0" max="30" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Time in Hospital (Days)</label>
                                            <input type="number" name="time_in_hospital" id="time_in_hospital" class="form-control" min="1" max="30" 
                                                   placeholder="0">
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Number of Procedures</label>
                                            <input type="number" name="num_procedures" id="num_procedures" class="form-control" min="0" max="20" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Number of Medications</label>
                                            <input type="number" name="num_medications" id="num_medications" class="form-control" min="0" max="30" 
                                                   placeholder="0">
                                        </div>
                                    </div>
                                </div>

                                <!-- Medication Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-pills me-2"></i>Medication Information</h6>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Medication Change</label>
                                            <select name="med_change" id="med_change" class="form-control">
                                                <option value="">Select Option</option>
                                                <option value="Yes">Yes</option>
                                                <option value="No">No</option>
                                                <option value="Unknown">Unknown</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Diabetes Medication</label>
                                            <select name="diabetes_med" id="diabetes_med" class="form-control">
                                                <option value="">Select Option</option>
                                                <option value="Yes">Yes</option>
                                                <option value="No">No</option>
                                                <option value="Unknown">Unknown</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>

                                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                    <a href="/view_patient/{patient_id}" class="btn btn-secondary me-md-2">Cancel</a>
                                    <button type="submit" class="btn btn-success btn-lg">
                                        <i class="fas fa-plus me-1"></i>Add Medical Record
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
        // Auto-fill functionality for existing patient data
        document.addEventListener('DOMContentLoaded', function() {{
            // Fetch existing patient data and pre-fill form
            fetch(`/api/patient_data/${{patient_email}}`)
                .then(response => response.json())
                .then(data => {{
                    if (data.success && data.patient_data) {{
                        // Auto-fill form fields with existing data
                        if (data.patient_data.age) document.getElementById('age').value = data.patient_data.age;
                        if (data.patient_data.gender) document.getElementById('gender').value = data.patient_data.gender;
                        if (data.patient_data.age_cat) document.getElementById('age_cat').value = data.patient_data.age_cat;
                        if (data.patient_data.medical_specialty) document.getElementById('medical_specialty').value = data.patient_data.medical_specialty;
                        if (data.patient_data.diagnosis) document.getElementById('diagnosis').value = data.patient_data.diagnosis;
                        if (data.patient_data.treatment) document.getElementById('treatment').value = data.patient_data.treatment;
                        if (data.patient_data.n_inpatient) document.getElementById('n_inpatient').value = data.patient_data.n_inpatient;
                        if (data.patient_data.n_lab_procedures) document.getElementById('n_lab_procedures').value = data.patient_data.n_lab_procedures;
                        if (data.patient_data.n_emergency) document.getElementById('n_emergency').value = data.patient_data.n_emergency;
                        if (data.patient_data.time_in_hospital) document.getElementById('time_in_hospital').value = data.patient_data.time_in_hospital;
                        if (data.patient_data.num_procedures) document.getElementById('num_procedures').value = data.patient_data.num_procedures;
                        if (data.patient_data.num_medications) document.getElementById('num_medications').value = data.patient_data.num_medications;
                        if (data.patient_data.num_diagnoses) document.getElementById('num_diagnoses').value = data.patient_data.num_diagnoses;
                        if (data.patient_data.med_change) document.getElementById('med_change').value = data.patient_data.med_change;
                        if (data.patient_data.diabetes_med) document.getElementById('doctor_name').value = data.patient_data.diabetes_med;
                        if (data.patient_data.doctor_name) document.getElementById('doctor_name').value = data.patient_data.doctor_name;
                        
                        // Show success message
                        showAutoFillMessage('Patient data pre-filled successfully!', 'success');
                    }}
                }})
                .catch(error => {{
                    console.error('Error fetching patient data:', error);
                }});
        }});

        function showAutoFillMessage(message, type) {{
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${{type}} alert-dismissible fade show`;
            alertDiv.innerHTML = `
                ${{message}}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            const form = document.getElementById('patientForm');
            form.insertBefore(alertDiv, form.firstChild);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {{
                if (alertDiv.parentNode) {{
                    alertDiv.remove();
                }}
            }}, 5000);
        }}
        </script>
    </body>
    </html>
    '''

@app.route('/patient/login', methods=['GET', 'POST'])
def patient_login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        
        try:
            conn = get_mysql_connection()
            try:
                with conn.cursor() as cursor:
                    execute_with_retry(cursor, """
                    SELECT * FROM users 
                    WHERE (username = %s OR email = %s) AND user_type = 'patient'
                """, (login, login))
                user = cursor.fetchone()
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                conn.close()
            
            if user:
                # Debug: Check if password hash verification works
                password_match = check_password_hash(user['password'], password)
                if password_match:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['user_type'] = user['user_type']
                    return redirect('/patient/dashboard')
                else:
                    error = f"Invalid password for user: {user['username']} (email: {user['email']}). Try 'patient123'"
            else:
                error = f"No patient found with login: {login}. Make sure the patient exists in the system."
        except Exception as e:
            error = f"Database error: {str(e)}"
    else:
        error = ""
    
    return f'''
    <html>
    <head><title>Patient Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header bg-success text-white">
                            <h4>👤 Patient Login</h4>
                        </div>
                        <div class="card-body">
                            {f"<div class='alert alert-danger'>{error}</div>" if error else ""}
                            <form method="POST">
                                <div class="mb-3">
                                    <label class="form-label">Username or Email</label>
                                    <input type="text" name="login" class="form-control" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" name="password" class="form-control" required>
                                </div>
                                <button type="submit" class="btn btn-success w-100">Login</button>
                            </form>
                            <div class="mt-3 text-center">
                                <small>Default: patient / patient123</small><br>
                                <a href="/" class="btn btn-link">← Back to Home</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/patient/dashboard')
def patient_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'patient':
        return redirect('/patient/login')
    
    # Get patient's medical records
    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT * FROM patient_data 
            WHERE patient_id = %s 
            ORDER BY created_at DESC
            LIMIT 1
        """, (session['user_id'],))
        medical_records = cursor.fetchall()
    conn.close()
    
    # Show only the latest prediction report
    if medical_records:
        latest_record = medical_records[0]  # Get the most recent record
        print(f"DEBUG: Patient dashboard - Doctor: '{latest_record.get('doctor_name')}', Risk: {latest_record.get('readmission_risk')}")
        print(f"DEBUG: Doctor ID: {latest_record.get('doctor_id')}")
        print(f"DEBUG: Record created at: {latest_record.get('created_at')}")
        print(f"DEBUG: Diagnosis: {latest_record.get('diagnosis')}")
        print(f"DEBUG: All record fields: {list(latest_record.keys())}")
        risk_color = "bg-danger" if latest_record['readmission_risk'] >= 70 else "bg-warning" if latest_record['readmission_risk'] >= 50 else "bg-success"
        risk_level = "High" if latest_record['readmission_risk'] >= 70 else "Medium" if latest_record['readmission_risk'] >= 50 else "Low"
        
        records_html = f'''
        <div class="card shadow">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0"><i class="fas fa-chart-line me-2"></i>Your Latest Readmission Risk Report</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-primary">Medical Information</h6>
                        <p><strong>Diagnosis:</strong> {latest_record['diagnosis'] or 'Not specified'}</p>
                        <p><strong>Treatment:</strong> {latest_record['treatment'] or 'Not specified'}</p>
                        <p><strong>Doctor:</strong> Dr. {latest_record['doctor_name'] or 'Unknown'}</p>
                        <p><strong>Date:</strong> {latest_record['created_at'].strftime('%B %d, %Y') if latest_record.get('created_at') else 'Unknown'}</p>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-primary">Risk Assessment</h6>
                        <div class="alert alert-{risk_color.replace('bg-', '')} text-center">
                            <h4 class="alert-heading">{latest_record['readmission_risk']}%</h4>
                            <p class="mb-0"><strong>Risk Level:</strong> {risk_level}</p>
                        </div>
                        <p><strong>Recommendations:</strong></p>
                        <p class="text-muted">
                            {"Immediate follow-up required. Consider extended monitoring." if latest_record['readmission_risk'] >= 70 else "Regular follow-up recommended. Monitor symptoms." if latest_record['readmission_risk'] >= 50 else "Standard follow-up schedule. Continue current treatment."}
                        </p>
                    </div>
                </div>
            </div>
        </div>
        '''
    else:
        records_html = '''
        <div class="text-center py-5">
            <i class="fas fa-file-medical fa-3x text-muted mb-3"></i>
            <h5>No medical reports available</h5>
            <p class="text-muted">Your medical reports will appear here once uploaded by your doctor.</p>
        </div>
        '''
    
    return f'''
    <html>
    <head><title>Patient Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-success">
            <div class="container">
                <a class="navbar-brand" href="/patient/dashboard">
                    <i class="fas fa-user-injured"></i> Patient Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="row">
                <div class="col-12">
                    <div class="card shadow-sm">
                        <div class="card-header bg-primary text-white">
                            <h5 class="card-title mb-0">
                                <i class="fas fa-file-medical me-2"></i>
                                Your Medical Reports (View Only)
                            </h5>
                        </div>
                        <div class="card-body">
                            {records_html}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/admin/reports')
def admin_reports():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')
    
    # Get statistics for reports
    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        # Total patients
        cursor.execute("SELECT COUNT(*) as total FROM users WHERE user_type = 'patient'")
        total_patients = cursor.fetchone()['total']
        
        # High risk patients
        cursor.execute("SELECT COUNT(*) as high_risk FROM patient_data WHERE readmission_risk >= 70")
        high_risk = cursor.fetchone()['high_risk']
        
        # Recent predictions
        cursor.execute("""
            SELECT pd.*, u.username 
            FROM patient_data pd 
            JOIN users u ON pd.patient_id = u.id 
            ORDER BY pd.created_at DESC LIMIT 10
        """)
        recent_predictions = cursor.fetchall()
    conn.close()
    
    predictions_html = ""
    for pred in recent_predictions:
        risk_color = "text-danger" if pred['readmission_risk'] >= 70 else "text-warning" if pred['readmission_risk'] >= 50 else "text-success"
        predictions_html += f'''
        <tr>
            <td>{pred['username']}</td>
            <td>{pred['diagnosis']}</td>
            <td class="{risk_color}">{pred['readmission_risk']:.1f}%</td>
            <td>{pred['created_at'].strftime('%Y-%m-%d') if pred.get('created_at') else 'Unknown'}</td>
        </tr>
        '''
    
    return f'''
    <html>
    <head><title>Admin Reports</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/admin/dashboard">
                    <i class="fas fa-user-md"></i> Admin Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card text-white bg-info">
                        <div class="card-body">
                            <h5 class="card-title">Total Patients</h5>
                            <h2>{total_patients}</h2>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-white bg-danger">
                        <div class="card-body">
                            <h5 class="card-title">High Risk Patients</h5>
                            <h2>{high_risk}</h2>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-white bg-success">
                        <div class="card-body">
                            <h5 class="card-title">Risk Rate</h5>
                            <h2>{(high_risk/total_patients*100) if total_patients > 0 else 0:.1f}%</h2>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0">Recent Predictions</h5>
                </div>
                <div class="card-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Patient</th>
                                <th>Diagnosis</th>
                                <th>Risk Score</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            {predictions_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        return redirect('/admin/login')
    
    if request.method == 'POST':
        try:
            # Get form data
            patient_email = request.form.get('patient_email', '')
            age = int(request.form['age'])
            gender = request.form['gender']
            diagnosis = request.form['diagnosis']
            treatment = request.form.get('treatment', '')
            doctor_name = request.form.get('doctor_name', '').strip()  # Use exactly what user enters
            if not doctor_name:  # Default if empty
                doctor_name = 'Unknown'
            
            # Additional medical fields with proper validation
            n_inpatient = request.form.get('n_inpatient', '0')
            n_lab_procedures = request.form.get('n_lab_procedures', '0')
            n_emergency = request.form.get('n_emergency', '0')
            medical_specialty = request.form.get('medical_specialty', '')
            age_cat = request.form.get('age_cat', '')
            med_change = request.form.get('med_change', '')
            diabetes_med = request.form.get('diabetes_med', '')
            time_in_hospital = request.form.get('time_in_hospital', '0')
            num_procedures = request.form.get('num_procedures', '0')
            num_medications = request.form.get('num_medications', '0')
            num_diagnoses = request.form.get('num_diagnoses', '0')
            
            # Convert to integers safely
            try:
                n_inpatient = int(n_inpatient) if n_inpatient else 0
                n_lab_procedures = int(n_lab_procedures) if n_lab_procedures else 0
                n_emergency = int(n_emergency) if n_emergency else 0
                time_in_hospital = int(time_in_hospital) if time_in_hospital else 0
                num_procedures = int(num_procedures) if num_procedures else 0
                num_medications = int(num_medications) if num_medications else 0
                num_diagnoses = int(num_diagnoses) if num_diagnoses else 0
            except (ValueError, TypeError):
                n_inpatient = n_lab_procedures = n_emergency = time_in_hospital = 0
                num_procedures = num_medications = num_diagnoses = 0
            
            # Generate a more sophisticated risk score based on multiple factors
            base_risk = random.randint(20, 80)
            
            # Adjust risk based on factors
            if n_inpatient > 5:
                base_risk += 15
            if n_emergency > 3:
                base_risk += 10
            if time_in_hospital > 7:
                base_risk += 12
            if num_medications > 10:
                base_risk += 8
            if num_diagnoses > 5:
                base_risk += 10
            if age_cat in ['elderly', 'very elderly']:
                base_risk += 15
            if medical_specialty in ['Cardiology', 'Neurology', 'Oncology']:
                base_risk += 8
            
            readmission_risk = min(100, max(0, base_risk))
            
            print(f"DEBUG: Predict form - Doctor name: '{doctor_name}', Risk: {readmission_risk}")
            
            # Save to database
            conn = get_mysql_connection()
            with conn.cursor() as cursor:
                # Find or create patient by email
                if patient_email:
                    cursor.execute("SELECT id FROM users WHERE email = %s AND user_type = 'patient'", (patient_email,))
                    patient_record = cursor.fetchone()
                    
                    if patient_record:
                        patient_id = patient_record['id']
                    else:
                        # Create new patient
                        username = patient_email.split('@')[0]
                        default_password = generate_password_hash('patient123')
                        
                        cursor.execute("""
                            INSERT INTO users (username, email, password, user_type) 
                            VALUES (%s, %s, %s, 'patient')
                        """, (username, patient_email, default_password))
                        patient_id = cursor.lastrowid
                else:
                    patient_id = None
                
                cursor.execute("""
                    INSERT INTO patient_data 
                    (patient_id, age, gender, diagnosis, treatment, doctor_id, doctor_name, readmission_risk,
                     n_inpatient, n_lab_procedures, n_emergency, medical_specialty, age_cat, 
                     med_change, diabetes_med, time_in_hospital, num_procedures, num_medications, num_diagnoses) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (patient_id, age, gender, diagnosis, treatment, session['user_id'], doctor_name, readmission_risk,
                      n_inpatient, n_lab_procedures, n_emergency, medical_specialty, age_cat,
                      med_change, diabetes_med, time_in_hospital, num_procedures, num_medications, num_diagnoses))
                
                print(f"DEBUG: Saved to database - Doctor: '{doctor_name}', Patient ID: {patient_id}")
            conn.commit()
            conn.close()
            
            # Determine risk level and recommendations
            if readmission_risk > 70:
                risk_level = "High"
                risk_color = "danger"
                recommendations = "Immediate follow-up required. Consider extended monitoring and specialized care plan."
                

            elif readmission_risk > 40:
                risk_level = "Medium"
                risk_color = "warning"
                recommendations = "Regular follow-up recommended. Monitor symptoms and medication adherence."
            else:
                risk_level = "Low"
                risk_color = "success"
                recommendations = "Standard follow-up schedule. Continue current treatment plan."
            
            return f'''
            <html>
            <head><title>Prediction Result</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
                <div class="container mt-5">
                    <div class="card shadow">
                        <div class="card-header bg-primary text-white">
                            <h4 class="mb-0"><i class="fas fa-chart-line me-2"></i>Readmission Risk Prediction Result</h4>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h5 class="text-primary">Patient Information</h5>
                                    <p><strong>Email:</strong> {patient_email or 'Not provided'}</p>
                                    <p><strong>Age:</strong> {age} years</p>
                                    <p><strong>Gender:</strong> {gender}</p>
                                    <p><strong>Diagnosis:</strong> {diagnosis}</p>
                                    <p><strong>Doctor:</strong> Dr. {doctor_name}</p>
                                    <p><strong>Specialty:</strong> {medical_specialty or 'Not specified'}</p>
                                </div>
                                <div class="col-md-6">
                                    <h5 class="text-primary">Risk Assessment</h5>
                                    <div class="alert alert-{risk_color}">
                                        <h4 class="alert-heading">Risk Score: {readmission_risk}%</h4>
                                        <p class="mb-0"><strong>Risk Level:</strong> {risk_level}</p>
                                    </div>
                                    <p><strong>Recommendations:</strong></p>
                                    <p class="text-muted">{recommendations}</p>
                                    

                                </div>
                            </div>
                            
                            <div class="mt-4">
                                <h6 class="text-primary">Medical Details</h6>
                                <div class="row">
                                    <div class="col-md-3">
                                        <small class="text-muted">Inpatient Visits</small>
                                        <p class="mb-0"><strong>{n_inpatient}</strong></p>
                                    </div>
                                    <div class="col-md-3">
                                        <small class="text-muted">Lab Procedures</small>
                                        <p class="mb-0"><strong>{n_lab_procedures}</strong></p>
                                    </div>
                                    <div class="col-md-3">
                                        <small class="text-muted">Emergency Visits</small>
                                        <p class="mb-0"><strong>{n_emergency}</strong></p>
                                    </div>
                                    <div class="col-md-3">
                                        <small class="text-muted">Hospital Days</small>
                                        <p class="mb-0"><strong>{time_in_hospital}</strong></p>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-4">
                                <a href="/predict" class="btn btn-primary me-md-2">
                                    <i class="fas fa-plus me-1"></i>Make Another Prediction
                                </a>
                                <a href="/admin/dashboard" class="btn btn-secondary">
                                    <i class="fas fa-arrow-left me-1"></i>Back to Dashboard
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
            function resendAlert() {{
                const button = event.target;
                const originalText = button.innerHTML;
                
                // Show loading state
                button.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Sending...';
                button.disabled = true;
                
                // Simulate resend (in real implementation, you'd call an API endpoint)
                setTimeout(() => {{
                    // Show success message
                    const alertDiv = document.createElement('div');
                    alertDiv.className = 'alert alert-success alert-dismissible fade show';
                    alertDiv.innerHTML = `
                        <i class="fas fa-check-circle me-2"></i>
                        <strong>Alert Resent Successfully!</strong> Email has been sent again to the patient.
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    `;
                    
                    // Insert at the top of the card body
                    const cardBody = document.querySelector('.card-body');
                    cardBody.insertBefore(alertDiv, cardBody.firstChild);
                    
                    // Reset button
                    button.innerHTML = originalText;
                    button.disabled = false;
                    
                    // Auto-remove alert after 5 seconds
                    setTimeout(() => {{
                        if (alertDiv.parentNode) {{
                            alertDiv.remove();
                        }}
                    }}, 5000);
                }}, 2000);
            }}
            </script>
            </body>
            </html>
            '''
        except Exception as e:
            error = str(e)
    else:
        error = ""
    
    return f'''
    <html>
    <head><title>Predict Readmission</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .form-section {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .form-section h6 {{
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 8px;
            margin-bottom: 20px;
        }}
        .auto-fill-info {{
            background: #e3f2fd;
            border: 1px solid #2196f3;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 15px;
        }}
    </style>
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <div class="container">
                <a class="navbar-brand" href="/admin/dashboard">
                    <i class="fas fa-user-md"></i> Admin Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <div class="row justify-content-center">
                <div class="col-md-10">
                    <div class="card shadow">
                        <div class="card-header bg-success text-white">
                            <h4 class="mb-0"><i class="fas fa-stethoscope me-2"></i>Hospital Readmission Prediction Form</h4>
                            <small>Comprehensive patient assessment for readmission risk prediction</small>
                        </div>
                        <div class="card-body">
                            {f"<div class='alert alert-danger'>{error}</div>" if error else ""}
                            
                            <!-- Auto-fill Information -->
                            <div class="auto-fill-info">
                                <i class="fas fa-info-circle me-2"></i>
                                <strong>Auto-fill Feature:</strong> Enter a patient email to automatically populate existing data and get visit statistics.
                            </div>
                            
                            <form method="POST" id="predictionForm">
                                <!-- Patient Information Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-user me-2"></i>Patient Information</h6>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Patient Email (Optional)</label>
                                            <input type="email" name="patient_email" id="patient_email" class="form-control" 
                                                   placeholder="patient@example.com">
                                            <small class="form-text text-muted">New patient will be created if email doesn't exist</small>
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Age *</label>
                                            <input type="number" name="age" id="age" class="form-control" min="1" max="120" required>
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Gender *</label>
                                            <select name="gender" id="gender" class="form-control" required>
                                                <option value="">Select Gender</option>
                                                <option value="Male">Male</option>
                                                <option value="Female">Female</option>
                                            </select>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Age Category</label>
                                            <select name="age_cat" id="age_cat" class="form-control">
                                                <option value="">Select Age Category</option>
                                                <option value="young">Young (18-30)</option>
                                                <option value="early-middle">Early Middle Age (31-45)</option>
                                                <option value="middle">Middle Age (46-60)</option>
                                                <option value="elderly">Elderly (61-75)</option>
                                                <option value="very elderly">Very Elderly (76+)</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Medical Specialty</label>
                                            <select name="medical_specialty" id="medical_specialty" class="form-control">
                                                <option value="">Select Specialty</option>
                                                <option value="Cardiology">Cardiology</option>
                                                <option value="Neurology">Neurology</option>
                                                <option value="Oncology">Oncology</option>
                                                <option value="Orthopedics">Orthopedics</option>
                                                <option value="General Medicine">General Medicine</option>
                                                <option value="Surgery">Surgery</option>
                                                <option value="Pediatrics">Pediatrics</option>
                                                <option value="Emergency Medicine">Emergency Medicine</option>
                                                <option value="Internal Medicine">Internal Medicine</option>
                                                <option value="Other">Other</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>

                                <!-- Medical History Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-history me-2"></i>Medical History</h6>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Primary Diagnosis *</label>
                                            <input type="text" name="diagnosis" id="diagnosis" class="form-control" required 
                                                   placeholder="Enter primary diagnosis...">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Number of Diagnoses</label>
                                            <input type="number" name="num_diagnoses" id="num_diagnoses" class="form-control" min="1" max="20" 
                                                   placeholder="Total diagnoses count">
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Treatment Plan</label>
                                            <textarea name="treatment" id="treatment" class="form-control" rows="3" 
                                                      placeholder="Describe treatment plan, medications, procedures..."></textarea>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Doctor Name *</label>
                                            <input type="text" name="doctor_name" id="doctor_name" class="form-control" required 
                                                   placeholder="Dr. Smith">
                                            <small class="form-text text-muted">Required for prediction analysis</small>
                                        </div>
                                    </div>
                                </div>

                                <!-- Visit Statistics Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-chart-bar me-2"></i>Visit Statistics</h6>
                                    <div class="row">
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Inpatient Visits</label>
                                            <input type="number" name="n_inpatient" id="n_inpatient" class="form-control" min="0" max="50" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Lab Procedures</label>
                                            <input type="number" name="n_lab_procedures" id="n_lab_procedures" class="form-control" min="0" max="100" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Emergency Visits</label>
                                            <input type="number" name="n_emergency" id="n_emergency" class="form-control" min="0" max="30" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-3 mb-3">
                                            <label class="form-label">Time in Hospital (Days)</label>
                                            <input type="number" name="time_in_hospital" id="time_in_hospital" class="form-control" min="1" max="30" 
                                                   placeholder="0">
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Number of Procedures</label>
                                            <input type="number" name="num_procedures" id="num_procedures" class="form-control" min="0" max="20" 
                                                   placeholder="0">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Number of Medications</label>
                                            <input type="number" name="num_medications" id="num_medications" class="form-control" min="0" max="30" 
                                                   placeholder="0">
                                        </div>
                                    </div>
                                </div>

                                <!-- Medication Section -->
                                <div class="form-section">
                                    <h6><i class="fas fa-pills me-2"></i>Medication Information</h6>
                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Medication Change</label>
                                            <select name="med_change" id="med_change" class="form-control">
                                                <option value="">Select Option</option>
                                                <option value="Yes">Yes</option>
                                                <option value="No">No</option>
                                                <option value="Unknown">Unknown</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Diabetes Medication</label>
                                            <select name="diabetes_med" id="diabetes_med" class="form-control">
                                                <option value="">Select Option</option>
                                                <option value="Yes">Yes</option>
                                                <option value="No">No</option>
                                                <option value="Unknown">Unknown</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>

                                <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                    <a href="/admin/dashboard" class="btn btn-secondary me-md-2">
                                        <i class="fas fa-arrow-left me-1"></i>Back to Dashboard
                                    </a>
                                    <button type="submit" class="btn btn-success btn-lg">
                                        <i class="fas fa-chart-line me-1"></i>Predict Readmission Risk
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
        // Auto-fill functionality for prediction form
        document.getElementById('patient_email').addEventListener('blur', function() {{
            const email = this.value;
            if (email) {{
                // Fetch patient data from database
                fetch(`/api/patient_data/${{email}}`)
                    .then(response => response.json())
                    .then(data => {{
                        if (data.success && data.patient_data) {{
                            // Auto-fill form fields
                            if (data.patient_data.age) document.getElementById('age').value = data.patient_data.age;
                            if (data.patient_data.gender) document.getElementById('gender').value = data.patient_data.gender;
                            if (data.patient_data.age_cat) document.getElementById('age_cat').value = data.patient_data.age_cat;
                            if (data.patient_data.medical_specialty) document.getElementById('medical_specialty').value = data.patient_data.medical_specialty;
                            if (data.patient_data.diagnosis) document.getElementById('diagnosis').value = data.patient_data.diagnosis;
                            if (data.patient_data.treatment) document.getElementById('treatment').value = data.patient_data.treatment;
                            if (data.patient_data.n_inpatient) document.getElementById('n_inpatient').value = data.patient_data.n_inpatient;
                            if (data.patient_data.n_lab_procedures) document.getElementById('n_lab_procedures').value = data.patient_data.n_lab_procedures;
                            if (data.patient_data.n_emergency) document.getElementById('n_emergency').value = data.patient_data.n_emergency;
                            if (data.patient_data.time_in_hospital) document.getElementById('time_in_hospital').value = data.patient_data.time_in_hospital;
                            if (data.patient_data.num_procedures) document.getElementById('num_procedures').value = data.patient_data.num_procedures;
                            if (data.patient_data.num_medications) document.getElementById('num_medications').value = data.patient_data.num_medications;
                            if (data.patient_data.num_diagnoses) document.getElementById('num_diagnoses').value = data.patient_data.num_diagnoses;
                            if (data.patient_data.med_change) document.getElementById('med_change').value = data.patient_data.med_change;
                            if (data.patient_data.diabetes_med) document.getElementById('diabetes_med').value = data.patient_data.diabetes_med;
                            if (data.patient_data.doctor_name) document.getElementById('doctor_name').value = data.patient_data.doctor_name;
                            
                            // Show success message
                            showAutoFillMessage('Patient data auto-filled successfully!', 'success');
                        }} else {{
                            showAutoFillMessage('No existing patient data found. New patient will be created.', 'info');
                        }}
                    }})
                    .catch(error => {{
                        console.error('Error:', error);
                        showAutoFillMessage('Error fetching patient data. Please check the email.', 'warning');
                    }});
            }}
        }});

        function showAutoFillMessage(message, type) {{
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${{type}} alert-dismissible fade show`;
            alertDiv.innerHTML = `
                ${{message}}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            const form = document.getElementById('predictionForm');
            form.insertBefore(alertDiv, form.firstChild);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {{
                if (alertDiv.parentNode) {{
                    alertDiv.remove();
                }}
            }}, 5000);
        }}
        </script>
    </body>
    </html>
    '''

@app.route('/management/login', methods=['GET', 'POST'])
def management_login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        
        # Check for default credentials
        if login == 'manager' and password == 'manager123':
            session['user_id'] = 999  # Dummy ID for manager
            session['username'] = 'manager'
            session['user_type'] = 'management'
            return redirect('/management/dashboard')
        
        try:
            conn = get_mysql_connection()
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM users 
                    WHERE (username = %s OR email = %s) AND user_type = 'management'
                """, (login, login))
                user = cursor.fetchone()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['user_type'] = user['user_type']
                return redirect('/management/dashboard')
            else:
                error = "Invalid credentials!"
        except Exception as e:
            error = f"Database error: {str(e)}"
    else:
        error = ""
    
    return f'''
    <html>
    <head><title>Management Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header bg-dark text-white">
                            <h4>🏢 Management Login</h4>
                        </div>
                        <div class="card-body">
                            {f"<div class='alert alert-danger'>{error}</div>" if error else ""}
                            <form method="POST">
                                <div class="mb-3">
                                    <label class="form-label">Username or Email</label>
                                    <input type="text" name="login" class="form-control" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" name="password" class="form-control" required>
                                </div>
                                <button type="submit" class="btn btn-dark w-100">Login</button>
                            </form>
                            <div class="mt-3 text-center">
                                <small>Default: manager / manager123</small><br>
                                <a href="/" class="btn btn-link">← Back to Home</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/management/dashboard')
def management_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'management':
        return redirect('/management/login')
    
    # Get analytics data
    conn = get_mysql_connection()
    with conn.cursor() as cursor:
        # Total statistics
        cursor.execute("SELECT COUNT(*) as total FROM users WHERE user_type = 'patient'")
        total_patients = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as total FROM patient_data")
        total_records = cursor.fetchone()['total']
        
        cursor.execute("SELECT AVG(readmission_risk) as avg_risk FROM patient_data")
        avg_risk = cursor.fetchone()['avg_risk'] or 0
        
        # High risk count
        cursor.execute("SELECT COUNT(*) as high_risk FROM patient_data WHERE readmission_risk >= 70")
        high_risk_count = cursor.fetchone()['high_risk']
        
        # Recent activity
        cursor.execute("""
            SELECT pd.*, u.username, pd.doctor_name
            FROM patient_data pd 
            JOIN users u ON pd.patient_id = u.id 
            ORDER BY pd.created_at DESC LIMIT 5
        """)
        recent_activity = cursor.fetchall()
    conn.close()
    
    activity_html = ""
    for activity in recent_activity:
        risk_color = "text-danger" if activity['readmission_risk'] >= 70 else "text-warning" if activity['readmission_risk'] >= 50 else "text-success"
        activity_html += f'''
        <tr>
            <td>{activity['username']}</td>
            <td>{activity['diagnosis']}</td>
            <td>{activity['doctor_name'] or 'Unknown'}</td>
            <td class="{risk_color}">{activity['readmission_risk']:.1f}%</td>
            <td>{activity['created_at'].strftime('%Y-%m-%d') if activity.get('created_at') else 'Unknown'}</td>
        </tr>
        '''
    
    return f'''
    <html>
    <head><title>Management Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
            <div class="container">
                <a class="navbar-brand" href="/management/dashboard">
                    <i class="fas fa-building"></i> Management Portal
                </a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Welcome, {session.get('username')}!</span>
                    <a class="nav-link" href="/logout">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <h2 class="mb-4">Management Dashboard</h2>
            
            <!-- KPI Cards -->
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="card text-white bg-primary">
                        <div class="card-body">
                            <h5 class="card-title">Total Patients</h5>
                            <h2>{total_patients}</h2>
                            <small>Registered patients</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-white bg-info">
                        <div class="card-body">
                            <h5 class="card-title">Total Records</h5>
                            <h2>{total_records}</h2>
                            <small>Medical records</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-white bg-warning">
                        <div class="card-body">
                            <h5 class="card-title">Average Risk</h5>
                            <h2>{avg_risk:.1f}%</h2>
                            <small>Readmission risk</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-white bg-danger">
                        <div class="card-body">
                            <h5 class="card-title">High Risk</h5>
                            <h2>{high_risk_count}</h2>
                            <small>Patients (≥70%)</small>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Recent Activity -->
            <div class="card">
                <div class="card-header bg-dark text-white">
                    <h5 class="mb-0">Recent Activity</h5>
                </div>
                <div class="card-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Patient</th>
                                <th>Diagnosis</th>
                                <th>Doctor</th>
                                <th>Risk Score</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            {activity_html}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/api/patient_data/<email>')
def get_patient_data(email):
    """API endpoint to get patient data for auto-filling forms"""
    try:
        conn = get_mysql_connection()
        try:
            with conn.cursor() as cursor:
                # Get the most recent patient data for this email
                execute_with_retry(cursor, """
                    SELECT pd.*, u.email, u.username
                    FROM patient_data pd
                    JOIN users u ON pd.patient_id = u.id
                    WHERE u.email = %s AND u.user_type = 'patient'
                    ORDER BY pd.created_at DESC
                    LIMIT 1
                """, (email,))
                
                patient_data = cursor.fetchone()
                
                if patient_data:
                    # Convert datetime objects to strings for JSON serialization
                    if patient_data.get('created_at'):
                        patient_data['created_at'] = patient_data['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                    
                    return jsonify({
                        'success': True,
                        'patient_data': patient_data
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': 'No patient data found'
                    })
                    
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            })
        finally:
            if 'conn' in locals():
                conn.close()
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    print("🚀 Starting Working Hospital App...")
    print("📊 Admin Login: admin / admin123")
    print("=" * 60)
    
    # Test database connection first
    print("🔍 Testing database connection...")
    if not test_database_connection():
        print("❌ Database connection failed! Please check your MySQL server and credentials.")
        print("💡 Make sure MySQL is running and the credentials in app_working.py are correct.")
        print("💡 Check if MySQL service is started on your system")
        exit(1)
    
    # Optimize database connection settings
    print("🔧 Optimizing database connection...")
    if optimize_database_connection():
        print("✅ Database connection optimized successfully")
    else:
        print("⚠️  Database optimization failed, continuing with default settings")
    
    print("🚀 Starting Flask application...")
    
    # Find an available port
    port = find_available_port(5000, 10)
    if port is None:
        print("❌ Could not find an available port. Exiting...")
        print("💡 Try closing other applications that might be using ports 5000-5009")
        exit(1)
    
    print(f"🌐 Starting Flask app on http://127.0.0.1:{port}")
    print(f"🌐 Alternative access: http://localhost:{port}")
    print(f"🔍 Health check: http://127.0.0.1:{port}/health")
    print("=" * 60)
    
    try:
        app.run(debug=True, host='127.0.0.1', port=port)
    except Exception as e:
        print(f"❌ Failed to start Flask app: {e}")
        print("💡 Try closing other applications that might be using the port")
        print("💡 Check if you have permission to bind to the port")
        exit(1)