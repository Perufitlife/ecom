from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    variants = StringField('Variants (comma separated)')
    submit = SubmitField('Add Product')

class EditProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    submit = SubmitField('Edit Product')

class VariantForm(FlaskForm):
    name = StringField('Variant Name', validators=[DataRequired()])
    submit = SubmitField('Add Variant')

class EditVariantForm(FlaskForm):
    name = StringField('Variant Name', validators=[DataRequired()])
    submit = SubmitField('Edit Variant')

class CountryForm(FlaskForm):
    name = StringField('Country Name', validators=[DataRequired()])
    submit = SubmitField('Add Country')

class EditCountryForm(FlaskForm):
    name = StringField('Country Name', validators=[DataRequired()])
    submit = SubmitField('Edit Country')

class RegionForm(FlaskForm):
    name = StringField('Region Name', validators=[DataRequired()])
    country_id = SelectField('Country', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Add Region')

class EditRegionForm(FlaskForm):
    name = StringField('Region Name', validators=[DataRequired()])
    country_id = SelectField('Country', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Edit Region')

class GoogleSheetForm(FlaskForm):
    sheet_id = StringField('Spreadsheet ID', validators=[DataRequired()])
    sheet_name = StringField('Sheet Name', validators=[DataRequired()])
    submit = SubmitField('Link Google Sheet')
