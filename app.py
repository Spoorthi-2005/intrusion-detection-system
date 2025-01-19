import os
import pickle
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from functools import wraps
from database import init_db, add_user, authenticate_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'

ALLOWED_EXTENSIONS = {'csv'}
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

model = pickle.load(open('model.pkl', 'rb'))


# Decorator to ensure login is required for certain routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if authenticate_user(username, password):
            flash('Username already exists!')
            return redirect(url_for('register'))

        add_user(username, email, password)
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate_user(username, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    return render_template('dashboard.html', username=username)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            session['uploaded_file'] = file_path
            flash(f'File "{filename}" uploaded successfully.')
            return redirect(url_for('check_packet'))

    return render_template('upload.html')


@app.route('/check-packet', methods=['GET'])
@login_required
def check_packet():
    if 'uploaded_file' not in session:
        flash('No uploaded file found. Please upload a file first.')
        return redirect(url_for('upload_file'))

    file_path = session['uploaded_file']
    try:
        data = pd.read_csv(file_path)

        # Normalize column names to handle case sensitivity or formatting issues
        data.columns = data.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('/', '_')

        required_columns = [
            'fwd_packet_length_max', 'avg_fwd_segment_size', 'subflow_fwd_bytes',
            'total_length_of_fwd_packets', 'flow_iat_max', 'flow_duration',
            'bwd_packet_length_std', 'packet_length_mean', 'init_win_bytes_forward',
            'init_win_bytes_backward', 'avg_bwd_segment_size', 'bwd_packets_s',
            'fwd_packets_s', 'average_packet_size', 'packet_length_std'
        ]

        if not all(col in data.columns for col in required_columns):
            missing_columns = [col for col in required_columns if col not in data.columns]
            flash(f'Missing required columns: {missing_columns}')
            return redirect(url_for('upload_file'))

        predictions = make_predictions(data)

        return render_template('upload.html', results=predictions)

    except Exception as e:
        flash(f'Error processing file: {e}')
        return redirect(url_for('upload_file'))


def make_predictions(data):
    results = []
    for _, row in data.iterrows():
        try:
            input_data = row[
                [
                    'fwd_packet_length_max', 'avg_fwd_segment_size', 'subflow_fwd_bytes',
                    'total_length_of_fwd_packets', 'flow_iat_max', 'flow_duration',
                    'bwd_packet_length_std', 'packet_length_mean', 'init_win_bytes_forward',
                    'init_win_bytes_backward', 'avg_bwd_segment_size', 'bwd_packets_s',
                    'fwd_packets_s', 'average_packet_size', 'packet_length_std'
                ]
            ].values.reshape(1, -1)
            prediction = model.predict(input_data)[0]
            results.append({
                'input': row.to_dict(),
                'prediction': 'BENIGN' if prediction == 0 else 'MALICIOUS'
            })
        except Exception as e:
            results.append({'input': row.to_dict(), 'error': f'Error: {e}'})
    return results


@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    if request.method == 'POST':
        try:
            required_fields = [
                'fwd_packet_length_max', 'avg_fwd_segment_size', 'subflow_fwd_bytes',
                'total_length_of_fwd_packets', 'flow_iat_max', 'flow_duration',
                'bwd_packet_length_std', 'packet_length_mean', 'init_win_bytes_forward',
                'init_win_bytes_backward', 'avg_bwd_segment_size', 'bwd_packets_s',
                'fwd_packets_s', 'average_packet_size', 'packet_length_std'
            ]

            features = []
            for field in required_fields:
                value = request.form.get(field)
                if not value:
                    flash(f'Missing value for field: {field}')
                    return redirect(url_for('predict'))
                features.append(float(value))

            prediction = model.predict([features])[0]
            result = 'BENIGN' if prediction == 0 else 'MALICIOUS'

            return render_template('predict.html', result=result)

        except ValueError:
            flash('Invalid input! Please enter numeric values only.')
            return redirect(url_for('predict'))
        except Exception as e:
            flash(f'Error during prediction: {e}')
            return redirect(url_for('predict'))

    return render_template('predict.html')


if __name__ == '__main__':
    app.run(debug=True)
