import os
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("MYSQL_PATH", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user_pool"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(20), nullable=False)
    
    #This will act like a List of BlogPost objects attached to each User. 
    #The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    #Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("user_pool.id"))
    #Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # build relationship between Comment & Blog_Posts
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    # build relationship between Comment & Users
    commenter_id = db.Column(db.Integer, db.ForeignKey("user_pool.id"))
    commenter = relationship("User", back_populates="comments")

    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


# Create admin_only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    new_form = RegisterForm()
    if new_form.validate_on_submit():
        # Email existed
        if User.query.filter_by(email=new_form.email.data).first():
            flash("You've already signed up with that email, please log in instead.")
            return redirect(url_for("login"))
        hash_and_salted_password = generate_password_hash(
            new_form.password.data,
            method="pbkdf2:sha256",
            salt_length=8
        )
        # print(f"I GET THE EMAIL: {new_form.email.data}")
        new_user = User(
            email=new_form.email.data,
            name=new_form.name.data,
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=new_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        user =  User.query.filter_by(email=email).first()
        # Email does not exist
        if not user:
            flash("That email does not exist. please try again.")
        # Password correct, Login successfully
        elif check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        # Password incorrect, re login
        else:
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))

    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET","POST"])
def show_post(post_id):
    comment_box = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_box.validate_on_submit():
        # Crutial: otherwise you can not submit and redirect
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(
            parent_post=requested_post,
            commenter=current_user,
            text=comment_box.text.data
        )
        db.session.add(new_comment)
        db.session.commit()
        redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, box=comment_box, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=False)
