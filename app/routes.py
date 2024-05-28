import os
import pickle
from flask import Blueprint, render_template, flash, redirect, url_for, request
from . import db
from .models import User, Product, Country, Region, Variant, LinkedSheet
from .forms import EditCountryForm, EditProductForm, EditRegionForm, EditVariantForm, GoogleSheetForm, LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm, ProductForm, CountryForm, RegionForm, VariantForm
from . import mail
from flask_mail import Message
from flask_login import current_user, login_user, logout_user, login_required
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

main_bp = Blueprint('main_bp', __name__)

@main_bp.route('/')
@login_required
def index():
    return render_template('index.html')

@main_bp.route('/products', methods=['GET', 'POST'])
@login_required
def products():
    form = ProductForm()
    if form.validate_on_submit():
        product = Product(name=form.name.data, user_id=current_user.id)
        db.session.add(product)
        db.session.commit()
        
        # Agregar variantes si se proporcionaron
        if form.variants.data:
            variants = [v.strip() for v in form.variants.data.split(',')]
            for variant_name in variants:
                variant = Variant(name=variant_name, product_id=product.id)
                db.session.add(variant)
            db.session.commit()
        
        flash('Product added successfully!')
        return redirect(url_for('main_bp.products'))
    
    products = Product.query.filter_by(user_id=current_user.id).all()
    return render_template('products.html', form=form, products=products)

@main_bp.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id:
        flash('You do not have permission to edit this product.')
        return redirect(url_for('main_bp.products'))
    form = EditProductForm()
    if form.validate_on_submit():
        product.name = form.name.data
        db.session.commit()
        flash('Product updated successfully!')
        return redirect(url_for('main_bp.products'))
    elif request.method == 'GET':
        form.name.data = product.name
    return render_template('edit_product.html', form=form)

@main_bp.route('/products/<int:product_id>/variants', methods=['GET', 'POST'])
@login_required
def variants(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id:
        flash('You do not have permission to view this product\'s variants.')
        return redirect(url_for('main_bp.products'))
    form = VariantForm()
    if form.validate_on_submit():
        variant = Variant(name=form.name.data, product_id=product_id)
        db.session.add(variant)
        db.session.commit()
        flash('Variant added successfully!')
        return redirect(url_for('main_bp.variants', product_id=product_id))
    variants = Variant.query.filter_by(product_id=product_id).all()
    return render_template('variants.html', form=form, product=product, variants=variants)

@main_bp.route('/products/<int:product_id>/variants/edit/<int:variant_id>', methods=['GET', 'POST'])
@login_required
def edit_variant(product_id, variant_id):
    variant = Variant.query.get_or_404(variant_id)
    product = Product.query.get_or_404(product_id)
    if variant.product.user_id != current_user.id:
        flash('You do not have permission to edit this variant.')
        return redirect(url_for('main_bp.variants', product_id=product_id))
    form = EditVariantForm()
    if form.validate_on_submit():
        variant.name = form.name.data
        db.session.commit()
        flash('Variant updated successfully!')
        return redirect(url_for('main_bp.variants', product_id=product_id))
    elif request.method == 'GET':
        form.name.data = variant.name
    return render_template('edit_variant.html', form=form, product=product)

@main_bp.route('/products/<int:product_id>/manage_variants', methods=['GET', 'POST'])
@login_required
def manage_variants(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id:
        flash('You do not have permission to manage variants for this product.')
        return redirect(url_for('main_bp.products'))

    form = VariantForm()
    if form.validate_on_submit():
        variant = Variant(name=form.name.data, product_id=product.id)
        db.session.add(variant)
        db.session.commit()
        flash('Variant added successfully!')
        return redirect(url_for('main_bp.manage_variants', product_id=product_id))
    
    variants = Variant.query.filter_by(product_id=product.id).all()
    return render_template('manage_variants.html', form=form, product=product, variants=variants)

@main_bp.route('/products/<int:product_id>/variants/delete/<int:variant_id>', methods=['POST'])
@login_required
def delete_variant(product_id, variant_id):
    variant = Variant.query.get_or_404(variant_id)
    if variant.product.user_id != current_user.id:
        flash('You do not have permission to delete this variant.')
        return redirect(url_for('main_bp.variants', product_id=product_id))
    db.session.delete(variant)
    db.session.commit()
    flash('Variant deleted successfully!')
    return redirect(url_for('main_bp.variants', product_id=product_id))

@main_bp.route('/products/delete/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id:
        flash('You do not have permission to delete this product.')
        return redirect(url_for('main_bp.products'))
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!')
    return redirect(url_for('main_bp.products'))

@main_bp.route('/countries', methods=['GET', 'POST'])
@login_required
def countries():
    form = CountryForm()
    if form.validate_on_submit():
        country = Country(name=form.name.data, user_id=current_user.id)
        db.session.add(country)
        db.session.commit()
        flash('Country added successfully!')
        return redirect(url_for('main_bp.countries'))
    countries = Country.query.filter_by(user_id=current_user.id).all()
    return render_template('countries.html', form=form, countries=countries)

@main_bp.route('/countries/edit/<int:country_id>', methods=['GET', 'POST'])
@login_required
def edit_country(country_id):
    country = Country.query.get_or_404(country_id)
    if country.user_id != current_user.id:
        flash('You do not have permission to edit this country.')
        return redirect(url_for('main_bp.countries'))
    form = EditCountryForm()
    if form.validate_on_submit():
        country.name = form.name.data
        db.session.commit()
        flash('Country updated successfully!')
        return redirect(url_for('main_bp.countries'))
    elif request.method == 'GET':
        form.name.data = country.name
    return render_template('edit_country.html', form=form)

@main_bp.route('/countries/delete/<int:country_id>', methods=['POST'])
@login_required
def delete_country(country_id):
    country = Country.query.get_or_404(country_id)
    if country.user_id != current_user.id:
        flash('You do not have permission to delete this country.')
        return redirect(url_for('main_bp.countries'))
    db.session.delete(country)
    db.session.commit()
    flash('Country deleted successfully!')
    return redirect(url_for('main_bp.countries'))

@main_bp.route('/regions', methods=['GET', 'POST'])
@login_required
def regions():
    form = RegionForm()
    form.country_id.choices = [(country.id, country.name) for country in Country.query.filter_by(user_id=current_user.id).all()]
    if form.validate_on_submit():
        region = Region(name=form.name.data, country_id=form.country_id.data, user_id=current_user.id)
        db.session.add(region)
        db.session.commit()
        flash('Region added successfully!')
        return redirect(url_for('main_bp.regions'))
    regions = Region.query.filter_by(user_id=current_user.id).all()
    return render_template('regions.html', form=form, regions=regions)

@main_bp.route('/regions/edit/<int:region_id>', methods=['GET', 'POST'])
@login_required
def edit_region(region_id):
    region = Region.query.get_or_404(region_id)
    if region.user_id != current_user.id:
        flash('You do not have permission to edit this region.')
        return redirect(url_for('main_bp.regions'))
    form = EditRegionForm()
    form.country_id.choices = [(country.id, country.name) for country in Country.query.filter_by(user_id=current_user.id).all()]
    if form.validate_on_submit():
        region.name = form.name.data
        region.country_id = form.country_id.data
        db.session.commit()
        flash('Region updated successfully!')
        return redirect(url_for('main_bp.regions'))
    elif request.method == 'GET':
        form.name.data = region.name
        form.country_id.data = region.country_id
    return render_template('edit_region.html', form=form)

@main_bp.route('/regions/delete/<int:region_id>', methods=['POST'])
@login_required
def delete_region(region_id):
    region = Region.query.get_or_404(region_id)
    if region.user_id != current_user.id:
        flash('You do not have permission to delete this region.')
        return redirect(url_for('main_bp.regions'))
    db.session.delete(region)
    db.session.commit()
    flash('Region deleted successfully!')
    return redirect(url_for('main_bp.regions'))

@main_bp.route('/orders', methods=['GET', 'POST'])
@login_required
def orders():
    form = GoogleSheetForm()
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    data = []

    if linked_sheet:
        data = get_google_sheet_data(linked_sheet.sheet_id, linked_sheet.sheet_name)

    if form.validate_on_submit():
        linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
        if linked_sheet:
            linked_sheet.sheet_id = form.sheet_id.data
            linked_sheet.sheet_name = form.sheet_name.data
        else:
            linked_sheet = LinkedSheet(sheet_id=form.sheet_id.data, sheet_name=form.sheet_name.data, user_id=current_user.id)
            db.session.add(linked_sheet)
        db.session.commit()
        flash('Google Sheet linked successfully!')
        return redirect(url_for('main_bp.orders'))

    return render_template('orders.html', form=form, data=data)

def get_google_sheet_data(sheet_id, sheet_name):
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                os.path.join(os.path.dirname(__file__), 'credentials.json'),
                ['https://www.googleapis.com/auth/spreadsheets.readonly']
            )
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('sheets', 'v4', credentials=creds)
    sheet = service.spreadsheets()
    result = sheet.values().get(spreadsheetId=sheet_id, range=sheet_name).execute()
    values = result.get('values', [])
    return values

@main_bp.route('/delete_linked_sheet', methods=['POST'])
@login_required
def delete_linked_sheet():
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    if linked_sheet:
        db.session.delete(linked_sheet)
        db.session.commit()
        flash('Linked sheet deleted successfully.')
    return redirect(url_for('main_bp.orders'))

@main_bp.route('/ads')
@login_required
def ads():
    return render_template('ads.html')

@main_bp.route('/inventory')
@login_required
def inventory():
    return render_template('inventory.html')

@main_bp.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')

@main_bp.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main_bp.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password')
            return redirect(url_for('main_bp.login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('main_bp.index'))
    return render_template('login.html', title='Sign In', form=form)

@main_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main_bp.login'))

@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main_bp.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('main_bp.login'))
    return render_template('register.html', title='Register', form=form)

@main_bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main_bp.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('main_bp.login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

@main_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main_bp.index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main_bp.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('main_bp.login'))
    return render_template('reset_password.html', form=form)

def send_password_reset_email(user):
    token = user.get_reset_password_token()
    msg = Message('Reset Your Password',
                  sender='hola@aztros.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('main_bp.reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    with mail.connect() as conn:
        conn.send(msg)
