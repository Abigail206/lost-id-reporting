import os
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from google.cloud import storage
from functools import wraps

# ---------------- GCS CONFIG ----------------
BUCKET_NAME = os.getenv('BUCKET_NAME', 'lost-id-recovery-uploads')
storage_client = storage.Client()
bucket = storage_client.bucket(BUCKET_NAME)

def upload_to_gcs(file, filename):
    blob = bucket.blob(filename)
    blob.upload_from_file(file)
    blob.make_public()
    return blob.public_url

# ---------------- FLASK APP CONFIG ----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change_this_secret_in_production_please')
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@/{os.getenv('DB_NAME')}"
    f"?unix_socket=/cloudsql/{os.getenv('CLOUD_SQL_CONNECTION_NAME')}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB limit

db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# ---------------- DATABASE MODELS ----------------
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(10), nullable=False)
    person_name = db.Column(db.String(200), nullable=False)
    id_type = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(500), nullable=True)
    contact_info = db.Column(db.String(300), nullable=True)
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# ---------------- HELPERS ----------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_admin_if_not_exists():
    admin = Admin.query.filter_by(username='admin').first()
    if not admin:
        admin = Admin(username='admin')
        admin.set_password('Passw0rd!')
        db.session.add(admin)
        db.session.commit()
        print("Created default admin -> username: admin, password: Passw0rd!")

def admin_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated

# ---------------- INITIALIZE DB ----------------
@app.before_first_request
def init_db():
    db.create_all()
    create_admin_if_not_exists()

# ---------------- ROUTES ----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/report', methods=['POST'])
def report():
    report_type = request.form.get('report_type')
    person_name = request.form.get('person_name')
    id_type = request.form.get('id_type')
    description = request.form.get('description')
    contact_info = request.form.get('contact_info')

    if not person_name or not id_type or not report_type:
        flash('Please fill required fields (Name, ID Type, Lost/Found).', 'danger')
        return redirect(url_for('index'))

    file = request.files.get('image')
    file_url = None
    if file and file.filename != '':
        if allowed_file(file.filename):
            filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
            file_url = upload_to_gcs(file, filename)
        else:
            flash('Invalid file type. Allowed: png, jpg, jpeg, gif', 'danger')
            return redirect(url_for('index'))

    new_report = Report(
        report_type=report_type,
        person_name=person_name,
        id_type=id_type,
        description=description,
        image_filename=file_url,
        contact_info=contact_info,
        status='Pending'
    )
    db.session.add(new_report)
    db.session.commit()
    return render_template('report_success.html', report=new_report)

# ---------------- ADMIN ROUTES ----------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            session['admin_username'] = admin.username
            flash('Logged in as admin.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_username', None)
    flash('Logged out.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_login_required
def admin_dashboard():
    q = request.args.get('q', '')
    filter_status = request.args.get('status', 'all')
    query = Report.query.order_by(Report.created_at.desc())
    if q:
        likeq = f"%{q}%"
        query = query.filter((Report.person_name.like(likeq)) |
                             (Report.description.like(likeq)) |
                             (Report.id_type.like(likeq)))
    if filter_status != 'all':
        query = query.filter_by(status=filter_status)
    reports = query.all()
    return render_template('admin_dashboard.html', reports=reports, filter_status=filter_status, q=q)

@app.route('/admin/report/<int:report_id>')
@admin_login_required
def view_report(report_id):
    report = Report.query.get_or_404(report_id)
    return render_template('view_report.html', report=report)

@app.route('/admin/report/<int:report_id>/action', methods=['POST'])
@admin_login_required
def report_action(report_id):
    action = request.form.get('action')
    report = Report.query.get_or_404(report_id)
    if action == 'verify':
        report.status = 'Verified'
        flash('Report marked Verified.', 'success')
    elif action == 'return':
        report.status = 'Returned'
        flash('Report marked Returned.', 'success')
    elif action == 'pending':
        report.status = 'Pending'
        flash('Report set to Pending.', 'info')
    else:
        flash('Unknown action.', 'warning')
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/about')
def about():
    return render_template('base.html', body="This is a small Lost ID Recovery system demo.")

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Max 5 MB allowed.', 'danger')
    return redirect(request.referrer or url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
