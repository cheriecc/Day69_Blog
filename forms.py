from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


# Create forms classes
class PostForm(FlaskForm):
    title = StringField(label='Post title', validators=[DataRequired()],)
    subtitle = StringField(label='Subtitle', validators=[DataRequired()])
    img_url = StringField(label='Image URL', validators=[DataRequired(), URL()])
    body = CKEditorField(label="Content", validators=[DataRequired()])
    submit = SubmitField(label="Submit")


class RegisterForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(), Email()], render_kw={'placeholder': 'Email'})
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8)], render_kw={'placeholder': 'Password'})
    username = StringField(label="Username", validators=[DataRequired()], render_kw={'placeholder': 'Username'})
    submit = SubmitField(label="Join now!")


class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired()], render_kw={'placeholder': 'Email'})
    password = PasswordField(label="Password", validators=[DataRequired()], render_kw={'placeholder': 'Password'})
    submit = SubmitField(label="Log in")


class ResetRequestForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired()], render_kw={'placeholder': 'Email'})
    submit = SubmitField(label="Reset Password")


class ChangeForm(FlaskForm):
    email = StringField(label="Email")
    password = PasswordField(label="New Password", validators=[DataRequired()], render_kw={'placeholder': 'Password'})
    confirm_password = PasswordField(label="Confirm Password", validators=[DataRequired()], render_kw={'placeholder': 'Confirm Password'})
    submit = SubmitField(label="Change Password")


class CommentForm(FlaskForm):
    text = CKEditorField(label="Comment", validators=[DataRequired()])
    submit = SubmitField(label="Submit Comment")
