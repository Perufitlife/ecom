from flask_wtf import FlaskForm
from wtforms import DateField, DecimalField, FieldList, Form, FormField, IntegerField, SelectField, SelectMultipleField, StringField, PasswordField, BooleanField, SubmitField
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
    sheet_id = StringField('Sheet ID', validators=[DataRequired()])
    sheet_name = StringField('Sheet Name', validators=[DataRequired()])
    submit = SubmitField('Load Sheet')

class ProductMappingForm(FlaskForm):
    product_id = SelectField('Product', validators=[DataRequired()], choices=[])
    sheet_header = SelectField('Sheet Header', validators=[DataRequired()], choices=[])
    sheet_products = SelectMultipleField('Sheet Products', validators=[DataRequired()], choices=[])
    submit = SubmitField('Map Product')

class EditProductMappingForm(FlaskForm):
    product_id = SelectField('Product', validators=[DataRequired()], choices=[])
    sheet_header = SelectField('Sheet Header', validators=[DataRequired()], choices=[])
    sheet_products = SelectMultipleField('Sheet Products', validators=[DataRequired()], choices=[])
    submit = SubmitField('Save Changes')

class DeleteProductMappingForm(FlaskForm):
    submit = SubmitField('Delete')

class CountryMappingForm(FlaskForm):
    country_id = SelectField('Select Country', coerce=int)
    sheet_header = SelectField('Select Sheet Header', choices=[])
    sheet_countries = SelectMultipleField('Select Countries from Sheet', choices=[], coerce=str)
    submit = SubmitField('Map Country')
    
class EditCountryMappingForm(CountryMappingForm):
    submit = SubmitField('Update Mapping')

class RegionMappingForm(FlaskForm):
    region_id = SelectField('Region', validators=[DataRequired()], coerce=int)
    sheet_header = SelectField('Sheet Header', validators=[DataRequired()])
    sheet_regions = SelectMultipleField('Sheet Regions', validators=[DataRequired()], coerce=str)
    submit = SubmitField('Map Region')

class EditRegionMappingForm(FlaskForm):
    region_id = SelectField('Region', validators=[DataRequired()], coerce=int)
    sheet_header = SelectField('Sheet Header', validators=[DataRequired()])
    sheet_regions = SelectMultipleField('Sheet Regions', validators=[DataRequired()], coerce=str)
    submit = SubmitField('Save Changes')

class AdAccountForm(Form):
    ad_account_id = StringField('Ad Account ID')

class AccountForm(FlaskForm):
    account_type = SelectField('Tipo de Cuenta', choices=[('facebook', 'Facebook'), ('tiktok', 'TikTok')], default='facebook')
    name = StringField('Nombre de la Cuenta', validators=[DataRequired()])
    token = StringField('Token', validators=[DataRequired()])
    ad_accounts = FieldList(FormField(AdAccountForm), min_entries=1)
    submit = SubmitField('Vincular Cuenta')



class TikTokAccountForm(FlaskForm):
    name = StringField('Nombre de la Cuenta', validators=[DataRequired()])
    access_token = StringField('Access Token', validators=[DataRequired()])
    advertiser_id = StringField('Advertiser ID', validators=[DataRequired()])
    submit = SubmitField('Vincular Cuenta')

class DeleteAccountForm(FlaskForm):
    submit = SubmitField('Eliminar')

class DateRangeForm(FlaskForm):
    start_date = StringField('Fecha de Inicio', validators=[DataRequired()])
    end_date = StringField('Fecha de Fin', validators=[DataRequired()])
    submit = SubmitField('Actualizar')


class KeywordForm(FlaskForm):
    keyword = StringField('Keyword', validators=[DataRequired()])

class AdMappingForm(FlaskForm):
    product_id = SelectField('Product', choices=[], coerce=int, validators=[DataRequired()])
    keywords = FieldList(FormField(KeywordForm), min_entries=1, max_entries=10)  # Asegúrate de que max_entries permite más de 2
    submit = SubmitField('Save')

class CountryAdMappingForm(FlaskForm):
    country_id = SelectField('Country', validators=[DataRequired()], choices=[])
    ad_countries = SelectMultipleField('Ad Countries', validators=[DataRequired()], choices=[])
    submit = SubmitField('Map Country')

class RegionAdMappingForm(FlaskForm):
    region_id = SelectField('Select Region', coerce=int)
    ad_regions = SelectMultipleField('Select Ad Regions', choices=[], coerce=str)
    submit = SubmitField('Map Region')

class EditRegionAdMappingForm(FlaskForm):
    region_id = SelectField('Region', validators=[DataRequired()], coerce=int)
    ad_regions = SelectMultipleField('Ad Regions', validators=[DataRequired()])
    submit = SubmitField('Save Changes')


class DeleteRegionAdMappingForm(FlaskForm):
    region_ids = SelectMultipleField('Regions', validators=[DataRequired()], coerce=int)
    submit = SubmitField('Delete Selected')

class FilterForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d')
    end_date = DateField('End Date', format='%Y-%m-%d')
    country = SelectField('Country', choices=[('all', 'All')])
    region = SelectField('Region', choices=[('all', 'All')])
    platform = SelectField('Platform', choices=[('all', 'All'), ('facebook', 'Facebook'), ('tiktok', 'TikTok')])
    currency = SelectField('Currency', choices=[('USD', 'USD'), ('PEN', 'PEN')])
    estado = SelectField('Estado', choices=[('all', 'All')])
    submit = SubmitField('Filter')

class WarehouseForm(FlaskForm):
    name = StringField('Warehouse Name', validators=[DataRequired()])
    country_id = SelectField('Country', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Submit')

class WarehouseProductForm(FlaskForm):
    product_id = SelectField('Product', coerce=int, validators=[DataRequired()])
    variant_id = SelectField('Variant', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    cost = DecimalField('Cost', validators=[DataRequired()])
    submit = SubmitField('Add Product')
