import flask_wtf
import wtforms
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField

# WTForm


class CreatePostForm(flask_wtf.FlaskForm):
    title = wtforms.StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = wtforms.StringField("Subtitle", validators=[DataRequired()])
    img_url = wtforms.StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = wtforms.SubmitField("Submit Post")


class LoginForm(flask_wtf.FlaskForm):
    email = wtforms.StringField("Email", validators=[wtforms.validators.DataRequired()])
    password = wtforms.PasswordField("Password", validators=[wtforms.validators.DataRequired()])
    submit = wtforms.SubmitField("Register")


class RegisterForm(flask_wtf.FlaskForm):
    email = wtforms.StringField("Email", validators=[wtforms.validators.DataRequired()])
    password = wtforms.PasswordField("Password", validators=[wtforms.validators.DataRequired()])
    name = wtforms.StringField("Name", validators=[wtforms.validators.DataRequired()])
    submit = wtforms.SubmitField("Register")


class CommentForm(flask_wtf.FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = wtforms.SubmitField("Submit comment")
