# Hospital Readmission Prediction System

A Flask-based web application for managing patient data and predicting readmission risks.

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- MySQL Server
- pip

### Installation

1. **Clone/Download the project**
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up MySQL database:**
   - Create database: `hospital_system`
   - Update `.env` file with your database credentials

4. **Run the application:**
   ```bash
   python app_working.py
   ```

5. **Access the application:**
   - Open: http://localhost:5000

## 🔑 Default Credentials

- **Admin Portal:** `admin` / `admin123`
- **Patient Portal:** `patient` / `patient123` (or any email with `patient123`)
- **Management Portal:** `manager` / `manager123`

## 📁 Project Structure

```
FLASK-PATIENT-APP/
├── app_working.py          # Main Flask application
├── requirements.txt         # Python dependencies
├── .env                    # Environment variables (create this)
├── hospital_system.db      # SQLite backup database
└── README.md              # This file
```

## 🎯 Features

- **Patient Management:** Add, view, edit, delete patients
- **Medical Records:** Comprehensive medical data entry
- **Risk Prediction:** AI-powered readmission risk assessment
- **Admin Dashboard:** Full CRUD operations
- **Patient Portal:** View-only medical reports
- **Management Analytics:** KPIs and performance metrics

## 🛠️ Technology Stack

- **Backend:** Flask (Python)
- **Database:** MySQL
- **Frontend:** Bootstrap 5 + Font Awesome
- **Authentication:** Session-based with password hashing
- **Architecture:** Single-file application with embedded HTML

## 📝 Environment Variables (.env)

Create a `.env` file in the project root:

```env
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=root
MYSQL_DATABASE=hospital_system
SECRET_KEY=your_secret_key_here
```

## 🔧 Database Setup

The application will automatically create the required tables on first run. If you need to manually set up the database:

1. Create MySQL database: `hospital_system`
2. Run the application - it will create tables automatically
3. Default admin user will be created: `admin` / `admin123`

## 🚨 Troubleshooting

- **Database Connection Error:** Check MySQL credentials in `.env`
- **Port Already in Use:** Change port in `app_working.py` line 2035
- **Import Errors:** Ensure all requirements are installed

## 📄 License

This project is for educational/demonstration purposes.

