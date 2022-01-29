from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import ForeignKey, Integer, Column
import re
import gravatarurl as avatar
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL_WORKS', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_name = db.Column(Integer, ForeignKey('user.name'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = relationship("User", back_populates="children")
    comments = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    children = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey("user.name"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


#db.create_all()


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return function(*args, **kwargs)
        else:
            return abort(403)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        is_admin = current_user.id
    else:
        is_admin = 0
    return render_template("index.html", all_posts=posts,
                           user=current_user.is_authenticated, is_admin=is_admin)


@app.route('/register', methods=["POST", "GET"])
def register():
    registration_form = RegisterForm()
    if registration_form.validate_on_submit():
        name = registration_form.name.data
        email = registration_form.email.data
        if User.query.filter_by(email=email).first() != None:
            flash("E-mail is already registered, login instead.")
            return redirect(url_for('login'))
        password = generate_password_hash(registration_form.password.data, method="pbkdf2:sha256",
                                          salt_length=8)
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user, force=True)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=registration_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        user = User.query.filter_by(email=email).first()
        if user == None:
            flash("Wrong e-mail")
            return redirect(url_for('login'))
        password = check_password_hash(user.password, login_form.password.data)
        if password == True:
            login_user(user, force=True)
            return redirect(url_for('get_all_posts'))
        else:
            flash("Wrong password")
            return redirect(url_for('login'))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("To post a comment you need to log in")
            return redirect(url_for('login'))
        comment = comment_form.body.data
        cleanr = re.compile('<.*?>')
        comment = re.sub(cleanr, '', comment)
        new_comment = Comment(text=comment, comment_author=current_user, post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()
    if current_user.is_authenticated:
        is_admin = current_user.id
    else:
        is_admin = 0
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()
    return render_template("post.html", post=requested_post,
                           is_admin=is_admin, user=current_user.is_authenticated,
                           form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", user=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", user=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    print(current_user)
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
    return render_template("make-post.html", form=form, user=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
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
        return redirect(url_for("show_post", post_id=post.id), user=current_user.is_authenticated)

    return render_template("make-post.html", form=edit_form, user=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(threaded=True)
