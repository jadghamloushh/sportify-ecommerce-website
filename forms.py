from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, RadioField, SelectField, IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange

class ReturnRequestForm(FlaskForm):
    reason = TextAreaField('Reason for Return', validators=[DataRequired()])
    quantity = IntegerField('Quantity to Return', validators=[DataRequired(), NumberRange(min=1, message="Quantity must be at least 1")])
    action = RadioField('Action', choices=[('refund', 'Refund'), ('replace', 'Replace')], validators=[DataRequired()])
    replacement_product_id = SelectField('Select Replacement Product', coerce=int, choices=[])
    submit = SubmitField('Submit Return Request')



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
