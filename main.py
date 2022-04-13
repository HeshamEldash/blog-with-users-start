from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from sqlalchemy import ForeignKey, Integer
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegistrationForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return db.session.query(User).get(id)



def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.id !=1:
            return abort(403)
        return function(*args, **kwargs)
    return decorated_function




##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="blog_posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = relationship("Comment", back_populates="parent_post")




class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False, unique=True)
    blog_posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates= "comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(), nullable=False, unique=False)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="comments")
    blog_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")






db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegistrationForm()
    error = None
    if form.validate_on_submit():
        print(form.email.data)
        print(form.password.data)

        if db.session.query(User).filter(User.email.in_([form.email.data])).all():
            error = "Email already in use"
        else:
            new_user = User(
                email=form.email.data,
                password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8),
                name=form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form, error=error)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.email == form.email.data).first()
        if user is None:
            error = "email not registered"
        else:
            if check_password_hash(user.password, form.password.data):
                login_user(user)

            else:
                error = "Incorrect password, Try again!"
    return render_template("login.html", form=form, error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST","GET"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                comment = comment_form.comment.data,
                user_id = current_user.id ,
                blog_id = requested_post.id

            )
            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, form=comment_form)
        else:
            flash("you need to login to save your comment")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
@admin_only
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():

        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
            # author_id = current_user
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
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

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
