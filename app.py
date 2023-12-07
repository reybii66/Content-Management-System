from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash , send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from jinja2 import FileSystemBytecodeCache
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired
from sqlalchemy.exc import SQLAlchemyError
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, or_
from sqlalchemy.orm import relationship
from flask_ckeditor import CKEditor
from flask_principal import Principal, RoleNeed, identity_loaded
from flask_principal import Permission 
from flask_uploads import UploadSet, configure_uploads, IMAGES, UploadNotAllowed
from flask_wtf.file import FileField, FileAllowed



app = Flask(__name__)
app.config['SECRET_KEY'] = 'key'  # Replace with a secret key for your application
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost/cms'  # SQLite database file
db = SQLAlchemy(app)

principal = Principal(app)
admin_role = RoleNeed('admin')
ckeditor = CKEditor(app)
admin_permission = Permission(admin_role)

# Configure Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin, db.Model):
    id = db.Column(db.String(20), primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    articles = relationship('Article', backref='author', lazy=True)
    @property
    def is_admin(self):
        # Define the criteria for an admin user (customize as needed)
        return admin_role in [role.name for role in self.roles]

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    pub_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.String(20), db.ForeignKey('user.id'), nullable=False)
    file_name = db.Column(db.String(255))  # Add this field for storing file names
    tags = db.Column(db.String(100))  # Modify this based on your requirements

class ArticleForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    tags = StringField('Tags')  # Modify this based on your requirements
    file = FileField('Attach File', validators=[FileAllowed(FileSystemBytecodeCache, 'File not allowed!')])
    submit = SubmitField('Submit')    
#db.create_all() # Uncomment to create tables initially


# Add role needs to the identity
@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Add roles to the user's identity
    if current_user.is_authenticated:
        # Check your criteria for determining admin status
        if current_user.is_admin:
            identity.add_role(admin_role)

@login_manager.user_loader
def load_user(user_id):
    if user_id in user:
        user = User()
        user.id = user_id
        return user

# Registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')




# Create an UploadSet for files and images
files = UploadSet('files', ('txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx'))
images = UploadSet('images', IMAGES)

# Configure the Flask app to use the UploadSets
app.config['UPLOADED_FILES_DEST'] = 'uploads/files'
app.config['UPLOADED_IMAGES_DEST'] = 'uploads/images'
configure_uploads(app, (files, images))

# Route to handle user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully. You can now log in.', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            flash('Error creating the account. Please try again.', 'danger')
            print(f"Error: {e}")
    return render_template('register.html', form=form)

# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')





# Route to handle login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.get(username)
        if user and user.password == password:
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)
# Route to handle logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    articles = Article.query.all()
    return render_template('index.html', articles=articles)

@app.route('/article/<int:article_id>')
@login_required
def article(article_id):
    article = Article.query.get(article_id)
    if article:
        return render_template('article.html', article=article)
    else:
        return "Article not found", 404

@app.route('/add_article', methods=['GET', 'POST'])
@login_required
def add_article():
    form = ArticleForm()
    if form.validate_on_submit():
        # Handle file upload
        file = form.file.data
        if file:
            try:
                filename = files.save(file)
            except UploadNotAllowed:
                flash('File type not allowed!', 'danger')
                return redirect(request.url)

            # Associate the file name with the article
            new_article.file_name = filename

        # Save the article to the database
        new_article = Article(
            title=form.title.data,
            content=form.content.data,
            tags=form.tags.data,
            author=current_user,
        )
        db.session.add(new_article)
        db.session.commit()

        flash('Article added successfully', 'success')
        return redirect(url_for('index'))

    return render_template('add_article.html', form=form)

# Route to edit an existing article
@app.route('/edit_article/<int:article_id>', methods=['GET', 'POST'])
@login_required
def edit_article(article_id):
    article = Article.query.get(article_id)
    form = ArticleForm(obj=article)
    if form.validate_on_submit():
        article.title = form.title.data
        article.content = form.content.data
        article.tags = form.tags.data
        db.session.commit()
        flash('Article updated successfully', 'success')
        return redirect(url_for('index'))
    return render_template('edit_article.html', form=form, article=article)

# Route to handle article deletion (restricted to admin)
@app.route('/delete_article/<int:article_id>')
@login_required
@admin_permission.require(http_exception=403)
def delete_article(article_id):
    article = Article.query.get(article_id)
    db.session.delete(article)
    db.session.commit()
    flash('Article deleted successfully', 'success')
    return redirect(url_for('index'))

# Route to handle user management (restricted to admin)
@app.route('/manage_users')
@login_required
@admin_permission.require(http_exception=403)
def manage_users():
    # Your user management logic here
    return render_template('manage_users.html')
# Custom error handler for 403 Forbidden errors
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@app.route('/uploads/<path:filename>')
def uploaded_files(filename):
    return send_from_directory(app.config['UPLOADED_FILES_DEST'], filename)

# Route to list all articles with pagination, search, and filters
@app.route('/article_list', methods=['GET'])
def article_list():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '')
    author_filter = request.args.get('author', '')
    tag_filter = request.args.get('tag', '')

    # Base query for articles
    articles_query = Article.query

    # Apply search filter
    if search_query:
        articles_query = articles_query.filter(
            or_(
                Article.title.ilike(f"%{search_query}%"),
                Article.content.ilike(f"%{search_query}%"),
                User.username.ilike(f"%{search_query}%")
            )
        )

    # Apply author filter
    if author_filter:
        articles_query = articles_query.join(User).filter(User.username == author_filter)

    # Apply tag filter
    if tag_filter:
        articles_query = articles_query.filter(Article.tags.ilike(f"%{tag_filter}%"))

    # Paginate the results
    articles = articles_query.paginate(page=page, per_page=10, error_out=False)

    # Get all users for the author filter dropdown
    users = User.query.all()

    return render_template('article_list.html', articles=articles, users=users) 

def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
    create_tables()
