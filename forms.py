from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.fields import EmailField
from wtforms.validators import DataRequired, URL, Email, Length, Regexp
from flask_ckeditor import CKEditorField # type: ignore


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users

class RegisterForm(FlaskForm):
    email = EmailField("Email", validators=[
        DataRequired(),
        Email(message="Enter a valid email address.")
    ])

    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$',
               message="Password must include uppercase, lowercase, and a number.")
    ])

    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")


# TODO: Create a LoginForm to log in existing users
class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[
        DataRequired(),
        Email(message="Enter a valid email address.")
    ])

    password = PasswordField("Password", validators=[
        DataRequired()
    ])

    submit = SubmitField("Login")


# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
