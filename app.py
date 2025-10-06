import os
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy

# ---------- Config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change_this_secret_in_production_please'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

db = SQLAlchemy(app)

# ---------- Models ----------
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(10), nullable=False)  # Lost or Found
    person_name = db.Column(db.String(200), nullable=False)
    id_type = db.Column(db.String(200), nullable=False)     # Student/Staff or other
    description = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(300), nullable=True)
    contact_info = db.Column(db.String(300), nullable=True)
    status = db.Column(db.String(50), default='Pending')   # Pending, Verified, Returned
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ---------- Helpers ----------
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


# ---------- Routes ----------
@app.before_first_request
def init_db():
    db.create_all()
    create_admin_if_not_exists()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/report', methods=['POST'])
def report():
    report_type = request.form.get('report_type')  # Lost or Found
    person_name = request.form.get('person_name')
    id_type = request.form.get('id_type')
    description = request.form.get('description')
    contact_info = request.form.get('contact_info')

    if not person_name or not id_type or not report_type:
        flash('Please fill required fields (Name, ID Type, Lost/Found).', 'danger')
        return redirect(url_for('index'))

    # Handle file upload
    file = request.files.get('image')
    filename = None
    if file and file.filename != '':
        if allowed_file(file.filename):
            filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            flash('Invalid file type. Allowed: png, jpg, jpeg, gif', 'danger')
            return redirect(url_for('index'))

    new_report = Report(
        report_type=report_type,
        person_name=person_name,
        id_type=id_type,
        description=description,
        image_filename=filename,
        contact_info=contact_info,
        status='Pending'
    )
    db.session.add(new_report)
    db.session.commit()
    return render_template('report_success.html', report=new_report)

# Serve uploaded files (Flask will serve from static by default; this route is convenience)
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Admin auth ---
def admin_login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated

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
        query = query.filter((Report.person_name.like(likeq)) | (Report.description.like(likeq)) | (Report.id_type.like(likeq)))
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
    action = request.form.get('action')  # verify, return, pending
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

# Simple contact page (optional)
@app.route('/about')
def about():
    return render_template('base.html', body="This is a small Lost ID Recovery system demo.")

# ---------- Error handlers ----------
@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Max 5 MB allowed.', 'danger')
    return redirect(request.referrer or url_for('index'))

# ---------- Run ----------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
