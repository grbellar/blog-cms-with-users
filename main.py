import flask
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm, RegisterForm, LoginForm
from functools import wraps
import flask_gravatar

app = Flask(__name__)
# app.config['SECRET_KEY'] =  # see secret key file
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

Base = declarative_base()

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = flask_gravatar.Gravatar(app=app,
                                   size=100,
                                   rating='g',
                                   default='retro',
                                   force_default=False,
                                   force_lower=False,
                                   use_ssl=False,
                                   base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CONFIGURE TABLES

class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    # Blog Post parent relationship
    posts = relationship("BlogPost", back_populates="author")
    # Comments parent relationship
    comments = relationship("Comment", back_populates="commenter")


# db.create_all()


class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    # Comments parent relationship
    comments = relationship("Comment", back_populates="blog_post")

    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


# db.create_all()


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # User child relationship
    commenter_id = db.Column(db.Integer, ForeignKey("users.id"))
    commenter = relationship("User", back_populates="comments")

    # Blog child relationship
    blog_post_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    blog_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)


# db.create_all()


def admin_only(func):
    @wraps(func)
    def wrapper():
        if current_user.is_authenticated and current_user.id == 1:
            return func()
        else:
            # would probably be better to redirect to the login page
            return flask.abort(403)
    return wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user=current_user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if flask.request.method == 'POST':
        user_exists = User.query.filter_by(email=form.email.data).first()
        if user_exists:
            flash("That email already exists. Try logging in instead.")
            return redirect(url_for('login'))
        else:
            pw_hash = generate_password_hash(form.password.data)
            new_user = User()
            new_user.name = form.name.data
            new_user.email = form.email.data
            new_user.password = pw_hash
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if flask.request.method == "POST":
        user_exists = User.query.filter_by(email=form.email.data).first()
        if user_exists:
            password_hash = user_exists.password
            if check_password_hash(password_hash, form.password.data):
                login_user(user_exists)
                return redirect(url_for('get_all_posts'))
            flash("Password incorrect.")
            return redirect(url_for('login'))
        flash("Email not found.")
        return redirect(url_for('login'))

    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["post", "get"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    comments = Comment.query.filter_by(blog_post_id=post_id)  # only return comments associated with the blog post
    if flask.request.method == "POST":
        if not current_user.is_authenticated:
            flash("You must be logged in to post your comment.")
            return redirect(url_for("login"))
        else:
            new_comment = Comment()
            new_comment.text = form.comment.data
            new_comment.commenter = current_user
            new_comment.blog_post = requested_post
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, user=current_user, logged_in=current_user.is_authenticated,
                           form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['POST', 'GET'])
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
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/", methods=['POST', 'GET'])
@admin_only
def edit_post():
    post_id = flask.request.args.get("post_id")
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


@app.route("/delete-post/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete-comment")
@admin_only
def delete_comment():
    comment_id = flask.request.args.get("comment_id")
    post_id = flask.request.args.get("post_id")
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(debug=True)
