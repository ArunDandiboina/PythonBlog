from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap # type: ignore
from flask_ckeditor import CKEditor # type: ignore
import hashlib
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user # type: ignore
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from sqlalchemy.exc import IntegrityError
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm # type: ignore
import os, dotenv, smtplib

dotenv.load_dotenv()

to_email = os.getenv("TO_EMAIL")
from_email = os.getenv("FROM_EMAIL")
app_password = os.getenv("APP")

def send_email(to_email, subject, message):
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            # connection.set_debuglevel(1) 
            connection.starttls()
            connection.login(user=from_email, password=app_password)
            connection.sendmail(
                from_addr=from_email,
                to_addrs=to_email,
                msg=f"Subject:{subject}\n\n{message}"
            )
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")
        

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
ckeditor = CKEditor(app)
bootstrap = Bootstrap(app)

# TODO: Configure Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True
}
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "blog_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(1000), nullable=False)

    # One-to-many: User → BlogPost
    posts = relationship("BlogPost", back_populates="author", cascade="all, delete")

    # One-to-many: User → Comment
    comments = relationship("Comment", back_populates="comment_author", cascade="all, delete")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # ForeignKey to User
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_users.id", ondelete="CASCADE"))
    author = relationship("User", back_populates="posts")

    # One-to-many: BlogPost → Comment
    comments = relationship("Comment", back_populates="parent_post", cascade="all, delete")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    # ForeignKey to User
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_users.id", ondelete="CASCADE"))
    comment_author = relationship("User", back_populates="comments")

    # ForeignKey to BlogPost
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id", ondelete="CASCADE"))
    parent_post = relationship("BlogPost", back_populates="comments")



with app.app_context():
    db.create_all()


def generate_gravatar(email, size=100, default='identicon', rating='g'):
    email = email.strip().lower().encode('utf-8')
    hash_email = hashlib.md5(email).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash_email}?s={size}&d={default}&r={rating}"

app.jinja_env.filters['gravatar'] = generate_gravatar

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        name = form.name.data
        if not email or not password or not name:
            flash("Please fill out all fields.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=email, password=hashed_password, name=name)
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()  # Undo the add
            flash("Email already exists. Please log in instead.")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash("Something went wrong. Please try again.")
            print(f"Registration error: {e}")
            return redirect(url_for('register'))
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        if not email or not password:
            flash("Please fill out all fields.")
            return redirect(url_for('login'))
        
        try:
            user = db.session.execute(db.select(User).where(User.email == email)).scalar_one_or_none()
            if not user:
                flash("Email not found. Please register.")
                return redirect(url_for('register'))
            if user and check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Invalid password.")
                form.password.data = ""
                return render_template("login.html", form=form)
        except Exception as e:
            flash("Something went wrong. Please try again.")
            print(f"Login error: {e}")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)        
    return decorated_function


@app.route('/')
@app.route('/page/<int:page>')
def get_all_posts(page=1):
    PER_PAGE = 3  # Change this to how many posts per page you want
    pagination = db.paginate(db.select(BlogPost).order_by(BlogPost.id.desc()), page=page, per_page=PER_PAGE)
    return render_template("index.html", all_posts=pagination.items, pagination=pagination)



# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Log in to contribute")
            return redirect(url_for('login'))
        
        new_comment = Comment(
            text=form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        try:
            db.session.add(new_comment)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash("Something went wrong while adding your comment.")
            print(f"Comment error: {e}")
            return redirect(url_for('show_post', post_id=post_id))
        form.comment_text.data = ""
    return render_template("post.html", post=requested_post, form=form)


# TODO: Use a decorator so only an admin user can create a new post
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


@app.route("/about")
def about():
    return render_template("about.html")


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Handle form submission
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        message = request.form.get('message')
        
        if not all([name, email, phone, message]):
            return render_template('contact.html', message="Please fill out all fields.")
        try:
            send_email(to_email, f"Message from {name}", f"Email: {email}\nPhone: {phone}\nMessage: {message}")
        except Exception:
            return render_template('contact.html', message=f"Failed to send the message.")
        return render_template('contact.html', message="Successfully sent your message!")
    return render_template('contact.html', message="Contact Me")



if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)
