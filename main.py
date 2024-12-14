from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy.exc import IntegrityError
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')

ckeditor = CKEditor(app)
Bootstrap5(app)



# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.get_or_404(User, user_id)
    except Exception:
        pass

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL") #"sqlite:///posts.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # Foreign key for author
    author_id: Mapped[int] = mapped_column(ForeignKey('users.id', name="fk_blog_users"), nullable=False)
    author: Mapped["User"] = relationship("User", back_populates="posts")
    
    # Relationship with comments
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="parent_post")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)

    # Relationships
    posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    # Foreign key for author
    author_id: Mapped[int] = mapped_column(ForeignKey('users.id', name="fk_comments_users"), nullable=False)
    comment_author: Mapped["User"] = relationship("User", back_populates="comments")

    # Foreign key for post
    post_id: Mapped[int] = mapped_column(ForeignKey('blog_posts.id', name="fk_blog_comment"), nullable=False)
    parent_post: Mapped["BlogPost"] = relationship("BlogPost", back_populates="comments")

# TODO: Create a admin_only decorator 
ALLOWED_ADMINS_ID = [1, 2]
def admin_only(f):
    @wraps(f)
    def is_admin(*args, **kwargs):
        if current_user.is_authenticated and current_user.id not in ALLOWED_ADMINS_ID:
            return abort(code=403)
        return f(*args, **kwargs)
    return is_admin


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form_register = RegisterForm()
    if form_register.validate_on_submit():
        try:
            existing_user = db.session.execute(db.select(User).where(User.email == form_register.email.data)).scalar()
            if existing_user:
                flash('This email already exist, please log in')
                return redirect(url_for('register'))
        except Exception:
            return redirect(url_for('register'))
        try:
            new_user = User(
                name=form_register.name.data,
                password=generate_password_hash(
                    password=form_register.password.data, 
                    method='pbkdf2', 
                    salt_length=8
                ),
                email=form_register.email.data
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('register'))
        except IntegrityError:
            db.session.rollback()
            flash('This email already exist, please log in')
            return redirect(url_for('register'))
    return render_template("register.html", form=form_register)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form_login = LoginForm()
    if form_login.validate_on_submit():
        get_user = db.session.execute(db.select(User).where(User.email == form_login.email.data)).scalar()
        if not get_user:
            flash('Wrong Email')
            return redirect(url_for('login'))
        if check_password_hash(pwhash=get_user.password, password=form_login.password.data):
            login_user(db.get_or_404(User, get_user.id))
            return redirect(url_for('get_all_posts'))
        else:
            flash('Password incorrect')
            return redirect(url_for('login'))
    return render_template("login.html", form=form_login)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route('/')
def get_all_posts():
    try:
        result = db.session.execute(db.select(BlogPost))
        posts = result.scalars().all()
        return render_template("index.html", all_posts=posts)
    except Exception as e:
        return render_template("index.html")

# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=comment_form.body.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, form=comment_form)
        else:
            flash('You need to login to comment')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=comment_form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        try:
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
        except Exception:
            flash('This title already exist, change to submit your post')
            return redirect(url_for("add_new_post"))
    return render_template("make-post.html", form=form)

# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)

# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete_comment/<int:comment_id>")
@admin_only
def delete_comment(comment_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=comment_to_delete.post_id))

@app.route("/delete/user")
@login_required
def delete_user():
    user_id = request.args.get('user_id')
    print(user_id)
    user_delete = db.get_or_404(User, user_id)
    logout_user()
    db.session.delete(user_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

if __name__ == "__main__":
    app.run(debug=False, port=os.environ.get('PGPORT'))
