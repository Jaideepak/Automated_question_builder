from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_file,session
import jwt
import datetime
from functools import wraps
import sqlite3
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from questiongenerator import QuestionGenerator
from fpdf import FPDF

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursecretkey'

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

# Serialize the keys
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Initialize question generator
qg = QuestionGenerator()

# JWT decorator to protect routes based on role
def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.cookies.get('jwt_token')
            if not token:
                return redirect(url_for('login'))
            try:
                decoded_token = jwt.decode(token, public_key_pem, algorithms=['RS256'])
                user_role = decoded_token.get('role')
                if roles and user_role not in roles:
                    return jsonify({'message': 'Unauthorized access!'}), 403
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired!'}), 403
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token!'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# SQLite database connection
def get_db_connection():
    conn = sqlite3.connect(r'C:\Users\SSN\Downloads\users.db')
    conn.row_factory = sqlite3.Row
    return conn

def generate_questions(article, num_que):
    if article.strip():
        if not num_que:
            num_que = 3
        generated_questions_list = qg.generate(article, num_questions=int(num_que))
        cleaned_questions = [f"{i+1}. {q.replace('pad>', '').replace('</s', '').strip()}?" for i, q in enumerate(generated_questions_list)]
        return cleaned_questions
    return []

# Function to save generated questions as PDF
def save_output_as_pdf(content, filepath):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', size=12)
    pdf.multi_cell(0, 10, content)
    
    # Use the filepath directly as it's already complete
    pdf.output(filepath)


# Login route for all roles
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role')

        conn = get_db_connection()
        role = request.form.get('role').lower()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ? AND role = ?', 
                            (username, password, role)).fetchone()

        conn.close()

        if user:
            token = jwt.encode({
                'user': username,
                'role': role,
                'exp': datetime.datetime.now() + datetime.timedelta(minutes=30)
            }, private_key_pem, algorithm='RS256')

            response = redirect(url_for(f'{role}_dashboard'))
            response.set_cookie('jwt_token', token, httponly=True)
            # In the login route for employees
            if user['role'] == 'employee':
                session['employee_id'] = user['id']  # Store employee ID in session

            # Handle trainers
            if role == 'trainer':
                # Check if trainer exists in trainers.db
                conn_trainers = sqlite3.connect(r'C:\Users\SSN\Downloads\trainers.db')
                trainer = conn_trainers.execute('SELECT trainer_id FROM trainer WHERE trainer_name = ?', 
                                                (username,)).fetchone()

                # If the trainer doesn't exist, add them to trainers.db
                if not trainer:
                    conn_trainers.execute('INSERT INTO trainer (trainer_name) VALUES (?)', (username,))
                    conn_trainers.commit()
                    trainer = conn_trainers.execute('SELECT trainer_id FROM trainer WHERE trainer_name = ?', 
                                                    (username,)).fetchone()

                conn_trainers.close()

                # Store trainer_id in session
                session['trainer_id'] = trainer[0]

            return response
        else:
            flash('Invalid credentials or role!')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/change_theme', methods=['POST'])
@token_required(roles=['admin'])
def change_theme():
    selected_theme = request.form.get('theme', 'default')
    session['theme_mode'] = selected_theme
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_dashboard')
@token_required(roles=['admin'])
def admin_dashboard():
    theme_mode = session.get('theme_mode', 'default')
    
    # Connect to users.db to fetch the number of employees and trainers
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch number of employees
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'employee'")
    num_employees = cursor.fetchone()[0]

    # Fetch number of trainers
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'trainer'")
    num_trainers = cursor.fetchone()[0]

    # Fetch all users for the user management section
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()

    # Connect to trainers.db to fetch the number of PDFs generated
    conn_trainers = sqlite3.connect(r'C:\Users\SSN\Downloads\trainers.db')
    cursor_trainers = conn_trainers.cursor()

    # Fetch number of PDFs generated
    cursor_trainers.execute("SELECT COUNT(*) FROM pdf_files")
    num_pdfs_generated = cursor_trainers.fetchone()[0]

    # Fetch all feedback entries to display in admin dashboard
    feedbacks = cursor_trainers.execute('''
        SELECT employee_id, trainer_id, pdf_filename, feedback_content 
        FROM feedback
    ''').fetchall()

    conn_trainers.close()

    # Pass the fetched data to the admin_dashboard.html template
    return render_template('admin_dashboard.html', 
                           theme_mode=theme_mode,
                           users=users,
                           num_employees=num_employees, 
                           num_trainers=num_trainers, 
                           num_pdfs_generated=num_pdfs_generated,
                           feedbacks=feedbacks)  # Pass feedbacks to the template

# Add user route (No change)
@app.route('/add_user', methods=['POST'])
@token_required(roles=['admin'])
def add_user():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    
    conn = get_db_connection()
    conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                 (username, password, role))
    conn.commit()
    conn.close()
    
    flash('User added successfully!')
    return redirect(url_for('admin_dashboard'))

# Update user route
@app.route('/update_user/<int:user_id>', methods=['POST'])
@token_required(roles=['admin'])
def update_user(user_id):
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    
    conn = get_db_connection()
    conn.execute('UPDATE users SET username = ?, password = ?, role = ? WHERE id = ?',
                 (username, password, role, user_id))
    conn.commit()
    conn.close()
    
    flash('User updated successfully!')
    return redirect(url_for('admin_dashboard'))

# Delete user route
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@token_required(roles=['admin'])
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully!')
    return redirect(url_for('admin_dashboard'))

# Trainer Dashboard
@app.route('/trainer_dashboard')
@token_required(roles=['trainer'])
def trainer_dashboard():
    trainer_id = session.get('trainer_id')

    if not trainer_id:
        flash('You need to be logged in as a trainer.')
        return redirect(url_for('login'))

    # Fetch the PDFs generated by this trainer
    conn = sqlite3.connect(r'C:\Users\SSN\Downloads\trainers.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT pdf_filename, generated_date FROM pdf_files WHERE trainer_id = ?', (trainer_id,))
    pdfs = cursor.fetchall()

    # Fetch feedback for this trainer's PDFs
    cursor.execute('''
        SELECT pdf_filename, feedback_content , employee_id 
        FROM feedback 
        WHERE trainer_id = ?
    ''', (trainer_id,))
    feedbacks = cursor.fetchall()

    conn.close()

    # Render the dashboard with PDFs and feedback
    return render_template('trainer_dashboard.html', pdfs=pdfs, feedbacks=feedbacks)

from flask import render_template, send_file, request, redirect, flash
import sqlite3
@app.route('/employee_dashboard')
@token_required(roles=['employee'])
def employee_dashboard():
    # Get the employee ID from the session
    employee_id = session.get('employee_id')
    
    if not employee_id:
        flash('You need to be logged in as an employee.')
        return redirect(url_for('login'))

    # Connect to trainers.db to fetch PDFs with trainer details
    conn_trainers = sqlite3.connect(r'C:\Users\SSN\Downloads\trainers.db')
    cursor_trainers = conn_trainers.cursor()
    
    # Fetch PDFs along with trainer name and trainer_id
    cursor_trainers.execute('''
        SELECT pdf_files.pdf_filename, pdf_files.generated_date, trainer.trainer_name, trainer.trainer_id
        FROM pdf_files
        JOIN trainer ON trainer.trainer_id = pdf_files.trainer_id
    ''')
    pdfs_with_trainers = cursor_trainers.fetchall()

    # Check if there are any feedback entries for the logged-in employee
    cursor_trainers.execute('''
        SELECT COUNT(*) FROM feedback WHERE employee_id = ?
    ''', (employee_id,))
    feedback_count = cursor_trainers.fetchone()[0]
     
    feedbacks = []
    if feedback_count > 0:
        # Fetch feedback submitted by the logged-in employee only if feedback exists
        cursor_trainers.execute('''
            SELECT pdf_filename, feedback_content 
            FROM feedback 
            WHERE employee_id = ?
        ''', (employee_id,))
        feedbacks = cursor_trainers.fetchall()

    conn_trainers.close()

    # Render the employee dashboard with the available PDFs and submitted feedback
    return render_template('employee_dashboard.html', 
                           pdfs_with_trainers=pdfs_with_trainers,
                           feedbacks=feedbacks)

# View PDF Route (Self Assessment)
@app.route('/view_pdf/<filename>')
@token_required(roles=['employee'])
def view_pdf(filename):
    return send_file(f'static/pdfs/{filename}', as_attachment=False)

@app.route('/submit_feedback', methods=['POST'])
@token_required(roles=['employee'])
def submit_feedback():
    employee_id = session.get('employee_id')
    
    if not employee_id:
        flash('You need to be logged in as an employee.')
        return redirect(url_for('login'))

    # Get data from form submission
    pdf_filename = request.form['pdf_filename']
    feedback_content = request.form['feedback_content']

    # Fetch the trainer_id associated with the PDF
    conn_trainers = sqlite3.connect(r'C:\Users\SSN\Downloads\trainers.db')
    cursor_trainers = conn_trainers.cursor()
    
    cursor_trainers.execute('''
        SELECT trainer_id FROM pdf_files WHERE pdf_filename = ?
    ''', (pdf_filename,))
    trainer_id = cursor_trainers.fetchone()[0]

    # Insert feedback into the feedback table
    cursor_trainers.execute('''
        INSERT INTO feedback (pdf_filename, feedback_content, employee_id, trainer_id)
        VALUES (?, ?, ?, ?)
    ''', (pdf_filename, feedback_content, employee_id, trainer_id))
    
    conn_trainers.commit()
    conn_trainers.close()

    flash('Feedback submitted successfully!')
    return redirect(url_for('employee_dashboard'))

# IT Support Dashboard (Dummy Page)
@app.route('/it_support_dashboard')
@token_required(roles=['it_support'])
def it_support_dashboard():
    return render_template('it_support_dashboard.html')
import csv
from flask import request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
import os

def process_csv_file(file):
    topics_and_contents = {}
    csv_file = file.read().decode('utf-8').splitlines()
    reader = csv.DictReader(csv_file)

    # Print CSV headers for debugging
    print("CSV Headers:", reader.fieldnames)
    
    topics = []
    for row in reader:
        topics.append(row['topics'])  # Make sure the header matches the CSV
        topics_and_contents[row['topics']] = row['content']  # Make sure the header matches the CSV
    return topics, topics_and_contents

@app.route('/get_topics_from_csv', methods=['POST'])
def get_topics_from_csv():
    file = request.files['file']
    if file and file.filename != '':
        topics, _ = process_csv_file(file)
        return jsonify({'topics': topics})
    return jsonify({'topics': []})
import os
import datetime
from flask import send_from_directory

# Function to save PDF and insert metadata into the database
def save_pdf_metadata(trainer_id, pdf_filename):
    conn = sqlite3.connect(r'C:\Users\SSN\Downloads\trainers.db')
    cursor = conn.cursor()
    
    generated_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Insert PDF metadata into the database
    cursor.execute('''
        INSERT INTO pdf_files (trainer_id, pdf_filename, generated_date)
        VALUES (?, ?, ?)
    ''', (trainer_id, pdf_filename, generated_date))
    
    conn.commit()
    conn.close()
    
@app.route('/generate_question_bank', methods=['POST'])
@token_required(roles=['trainer'])
def generate_question_bank():
    if 'trainer_id' not in session:
        return redirect('/login')

    trainer_id = session['trainer_id']  # Retrieve trainer_id from session
    topic = request.form['topics']
    num_questions = request.form['num_questions']
    file = request.files.get('file')

    if file and file.filename != '':
        _, csv_data = process_csv_file(file)
        article = csv_data.get(topic, "")

    if article:
        generated_questions = generate_questions(article, num_questions)
        if generated_questions:
            # Save the PDF to the static folder
            pdf_filename = f"questions_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
            pdf_path = os.path.join('static', 'pdfs', pdf_filename)
            save_output_as_pdf('\n'.join(generated_questions), pdf_path)

            # Insert PDF metadata into the database using trainer_id
            save_pdf_metadata(trainer_id, pdf_filename)

    # **Re-fetch the list of PDFs to ensure they appear after the new one is generated**
    conn = sqlite3.connect(r'C:\Users\SSN\Downloads\trainers.db')
    cursor = conn.cursor()
    cursor.execute('SELECT pdf_filename, generated_date FROM pdf_files WHERE trainer_id = ?', (trainer_id,))
    pdfs = cursor.fetchall()
    conn.close()

    # **Pass the list of PDFs to the template**
    return render_template('trainer_dashboard.html', generated_questions=generated_questions, pdf_filename=pdf_filename, pdfs=pdfs)

# Route to download PDF
# Route to download the generated PDF
@app.route('/download_pdf/<filename>')
def download_pdf(filename):
    return send_from_directory('static/pdfs', filename, as_attachment=True)

import PyPDF2

@app.route('/edit_pdf/<filename>', methods=['GET', 'POST'])
@token_required(roles=['trainer'])
def edit_pdf(filename):
    pdf_path = os.path.join('static', 'pdfs', filename)

    if request.method == 'POST':
        # Save the updated content as a new PDF (or overwrite)
        new_content = request.form['content']
        save_output_as_pdf(new_content, pdf_path)  # Save changes
        flash('PDF has been updated successfully!')
        return redirect(url_for('trainer_dashboard'))

    # If GET, extract text content from the PDF for editing
    with open(pdf_path, 'rb') as f:  # Open as binary
        reader = PyPDF2.PdfReader(f)
        content = ''
        for page in reader.pages:
            content += page.extract_text()  # Extract text from each page

    return render_template('edit_pdf.html', content=content, filename=filename)

import base64
from io import BytesIO
from PIL import Image
from flask import request, send_file
from fpdf import FPDF
import sqlite3

# Generate System Monitoring Report as PDF
@app.route('/generate_pdf_report', methods=['POST'])
@token_required(roles=['admin'])
def generate_pdf_report():
    # Retrieve the necessary data
    conn = get_db_connection()
    num_employees = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'employee'").fetchone()[0]
    num_trainers = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'trainer'").fetchone()[0]

    conn_trainers = sqlite3.connect(r'C:\Users\SSN\Downloads\trainers.db')
    num_pdfs_generated = conn_trainers.execute("SELECT COUNT(*) FROM pdf_files").fetchone()[0]
    
    conn.close()
    conn_trainers.close()

    # Get the chart images from the form submission
    chart_data_pie = request.form['chartDataPie']
    chart_data_bar = request.form['chartDataBar']

    # Remove the 'data:image/png;base64,' prefix from the base64 data
    chart_data_pie = chart_data_pie.split(',')[1]
    chart_data_bar = chart_data_bar.split(',')[1]

    # Decode the base64 data
    pie_image_data = base64.b64decode(chart_data_pie)
    bar_image_data = base64.b64decode(chart_data_bar)

    # Load the images from the decoded data using PIL
    pie_image = Image.open(BytesIO(pie_image_data))
    bar_image = Image.open(BytesIO(bar_image_data))

    pie_image_path = 'pie_chart.png'
    bar_image_path = 'bar_chart.png'

    pie_image.save(pie_image_path)
    bar_image.save(bar_image_path)

    # Create a new PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add content to the PDF
    pdf.cell(200, 10, txt="System Monitoring Report", ln=True, align='C')
    pdf.ln(10)

    pdf.cell(200, 10, txt=f"Number of Employees: {num_employees}", ln=True)
    pdf.cell(200, 10, txt=f"Number of Trainers: {num_trainers}", ln=True)
    pdf.cell(200, 10, txt=f"Number of PDFs Generated: {num_pdfs_generated}", ln=True)

    pdf.ln(10)  # Line break before the charts

    # Insert Pie Chart into PDF
    pdf.image(pie_image_path, x=10, y=60, w=90)  # Adjust positioning and size as needed

    # Insert Bar Chart into PDF
    pdf.image(bar_image_path, x=110, y=60, w=90)  # Adjust positioning and size as needed

    # Save the PDF
    pdf_filename = "system_monitoring_report.pdf"
    pdf.output(pdf_filename)

    # Serve the PDF for download
    return send_file(pdf_filename, as_attachment=True)


# Generate User Management Report as PDF
@app.route('/generate_user_management_pdf', methods=['POST'])
@token_required(roles=['admin'])
def generate_user_management_pdf():
    # Retrieve all users' usernames and roles from the database
    conn = get_db_connection()
    users = conn.execute("SELECT username, role FROM users").fetchall()
    conn.close()

    # Create a new PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add a title to the PDF
    pdf.cell(200, 10, txt="User Management Report", ln=True, align='C')
    pdf.ln(10)  # Line break

    # Add table headers
    pdf.cell(100, 10, txt="Username", border=1)
    pdf.cell(100, 10, txt="Role", border=1)
    pdf.ln(10)

    # Add user data to the PDF
    for user in users:
        pdf.cell(100, 10, txt=user['username'], border=1)
        pdf.cell(100, 10, txt=user['role'], border=1)
        pdf.ln(10)

    # Save the PDF to a file
    pdf_filename = "user_management_report.pdf"
    pdf.output(pdf_filename)

    # Serve the PDF for download
    return send_file(pdf_filename, as_attachment=True)


@app.context_processor
def inject_user():
    # This context processor will inject the user's name and role into every template
    token = request.cookies.get('jwt_token')
    if token:
        try:
            decoded_token = jwt.decode(token, public_key_pem, algorithms=['RS256'])
            user_name = decoded_token.get('user')
            user_role = decoded_token.get('role')
            return dict(user_name=user_name, user_role=user_role)
        except jwt.ExpiredSignatureError:
            return dict(user_name=None, user_role=None)
        except jwt.InvalidTokenError:
            return dict(user_name=None, user_role=None)
    return dict(user_name=None, user_role=None)
    
@app.route('/logout')
def logout():
    response = redirect(url_for('login'))
    response.set_cookie('jwt_token', '', expires=0)  # Clear the JWT token
    flash('You have been logged out.')
    return response

if __name__ == "__main__":
    if not os.path.exists('static'):
        os.makedirs('static')  # Create static folder for storing PDF
    app.run(debug=True)
