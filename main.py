import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_from_directory
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
import sqlalchemy.dialects.sqlite
from flask_wtf.csrf import CSRFProtect
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from forms import PostForm, RegisterForm, LoginForm, CommentForm, ResetRequestForm, ChangeForm
from datetime import date
import jwt
from time import time
from flask_mail import Mail, Message

# Create APP
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('START_KEY')
app.config['SECRET_KEY'] = os.environ.get('START_KEY')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MY_EMAIL')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASSWORD')
Bootstrap(app)
CKEditor(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_lower=False, use_ssl=False, base_url=None)
csrf = CSRFProtect(app)
csrf.init_app(app)
mail = Mail(app)


# Connect to DB (if DB exists)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('MYSQL_PATH', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


# Create tables for DB
class User(UserMixin, db.Model):
    __tablename__ = 'user_pool'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(20), nullable=False)
    # Link User table with BlogPost_author
    posts = relationship('BlogPost', back_populates='author')
    # Link User table with Comment_commenter
    comments = relationship('Comment', back_populates='commenter')

    def get_token(self, expire_in=3600):
        token = jwt.encode(
            {'encoded': self.id, 'exp': time() + expire_in},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return token

    @staticmethod
    def verify_token(token):
        try:
            user_id = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')['encoded']
        except:
            return None
        return User.query.get(user_id)


class BlogPost(db.Model):
    __tablename__ = 'blog_posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    # Link Author column with User table
    author_id = db.Column(db.Integer, db.ForeignKey('user_pool.id'))
    author = relationship('User', back_populates='posts')
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Link BlogPost table with Comment_subject_post
    comments = relationship('Comment', back_populates='subject_post')


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # Link Subject_post column with Post table
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    subject_post = relationship('BlogPost', back_populates='comments')
    # Link Commenter column with User table
    commenter_id = db.Column(db.Integer, db.ForeignKey('user_pool.id'))
    commenter = relationship('User', back_populates='comments')


class Message(db.Model):
    __tablename__ = 'message_box'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    message = db.Column(db.String(250), nullable=False)

# Create DB (if DB does not exist)
with app.app_context():
    db.create_all()


# Create admin_only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    posts = BlogPost.query.all()
    return render_template("index.html", posts=posts, current_user=current_user)


@app.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    register_form.validate_on_submit()
    if request.method == "POST":
        email = register_form.email.data
        unhashed_pw = register_form.password.data
        username = register_form.username.data
        if User.query.filter_by(email=email).first():
            flash(f'You has already registered with this email account <{email}>, please log in.', 'error-msg')
            return redirect(url_for('login'))
        else:
            hashed_pw = generate_password_hash(
                password=unhashed_pw,
                method="pbkdf2:sha256",
                salt_length=8
            )
            new_user = User(
                email=email,
                password=hashed_pw,
                name=username
            )
            db.session.add(new_user)
            db.session.commit()
            flash(f'Congratulations! {new_user.name} You have successfully signed up!', 'success-msg')
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    login_form.validate_on_submit()
    if request.method == "POST":
        email = login_form.email.data
        unhashed_password = login_form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('This account does not exist, please check and try again.', 'error-msg')
        elif check_password_hash(user.password, unhashed_password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('The password is not correct, please check and try again.', 'error-msg')
    return render_template("login.html", form=login_form)


@app.route("/post/<post_id>", methods=["GET", "POST"])
def post(post_id):
    comment_box = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash('You need to login or register before comment.', 'error-msg')
            return redirect(url_for('login'))
        new_comment = Comment(
            subject_post=requested_post,
            commenter=current_user,
            text=comment_box.text.data
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('post', post_id=requested_post.id))
    return render_template("post.html", form=comment_box, post=requested_post, current_user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_post():
    post_form = PostForm()
    post_form.validate_on_submit()
    if request.method == "POST":
        new_post = BlogPost(
            title=post_form.title.data,
            subtitle=post_form.subtitle.data,
            author=current_user,
            img_url=post_form.img_url.data,
            body=post_form.body.data,
            date=date.today().strftime('%B %d, %Y')
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('post', post_id=new_post.id))
    return render_template("edit.html", form=post_form, current_user=current_user)


@app.route("/edit-post/<post_id>", methods=["GET", "POST"])
@admin_only
def edit(post_id):
    edit_post = BlogPost.query.get(post_id)
    edit_form = PostForm(
        title=edit_post.title,
        subtitle=edit_post.subtitle,
        img_url=edit_post.img_url,
        author=edit_post.author,
        body=edit_post.body
    )
    edit_form.validate_on_submit()
    if request.method == "POST":
        edit_post.title = edit_form.title.data
        edit_post.subtitle = edit_form.subtitle.data
        edit_post.img_url = edit_form.img_url.data
        edit_post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for('post', post_id=edit_post.id))
    return render_template("edit.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<post_id>")
@admin_only
def delete(post_id):
    post_selected = BlogPost.query.get(post_id)
    db.session.delete(post_selected)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        new_msg = Message(
            name=request.form["name"],
            email=request.form["email"],
            message=request.form["message"]
        )
        db.session.add(new_msg)
        db.session.commit()
        flash(f'Hi {request.form["name"]}, thanks for contacting me, I will get back to you as soon as possible!', 'success-msg')
        return redirect(url_for('home'))
    return render_template("contact.html")


@app.route("/about")
def about():
    return render_template("about.html")


# Create a function to send email
def send_mail(user):
    token = user.get_token()
    msg = Message(f'Password Reset Email',
                  recipients=[user.email],
                  sender=app.config['MAIL_USERNAME']
                  )
    msg.body = f''' Hi {user.name}, in order to reset your password, please follow the link below.\n
    {url_for('reset_on', token=token, _external=True)}\n
    Please note: this link will be valid for only 1 hour!\n
    If you did not request this, please ignore this email.'''
    mail.send(msg)


@app.route("/reset", methods=["GET", "POST"])
def reset():
    reset_form = ResetRequestForm()
    reset_form.validate_on_submit()
    if request.method == "POST":
        email = reset_form.email.data
        reset_user = User.query.filter_by(email=email).first()
        if not reset_user:
            flash('This email does not exist, please register a new account.', 'error-msg')
            return redirect(url_for('register'))
        else:
            send_mail(reset_user)
            flash('Reset request sent, please check your email.', 'success-msg')
            return redirect(url_for('home'))
    return render_template("reset_pw.html", form=reset_form)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_on(token):
    reset_user = User.verify_token(token)
    if reset_user == None:
        flash('That token is not correct, please try again', 'error-msg')
        return redirect(url_for('reset'))
    reset_pw_form = ChangeForm()
    reset_pw_form.validate_on_submit()
    if request.method == "POST":
        if reset_pw_form.password.data != reset_pw_form.confirm_password.data:
            flash('Your new password does not match confirmation.', 'error-msg')
            return redirect(url_for('reset_on', token=token))
        hashed_password = generate_password_hash(
            password=reset_pw_form.password.data,
            method="pbkdf2:sha256",
            salt_length=8
        )
        reset_user.password = hashed_password
        db.session.commit()
        login_user(reset_user)
        flash('Your password has been changed successfully!', 'success-msg')
        return redirect(url_for('home'))
    return render_template("change_pw.html", form=reset_pw_form, user=reset_user)