from datetime import datetime, timezone
import os
import pickle
import google_auth_oauthlib.flow
import google.oauth2.credentials
from flask import Blueprint, app, current_app, json, jsonify, render_template, flash, redirect, session, url_for, request
import requests
from . import db
from .models import Account, AdMapping, CampaignData, CountryAdMapping, CountryMapping, GoogleSheet, ProductMapping, RegionAdMapping, RegionMapping, SheetData, SheetHeaders, User, Product, Country, Region, Variant, LinkedSheet, Warehouse, WarehouseProduct
from .forms import AccountForm, AdMappingForm, CountryAdMappingForm, CountryMappingForm, DateRangeForm, DeleteAccountForm, DeleteRegionAdMappingForm, EditCountryForm, EditCountryMappingForm, EditProductForm, EditProductMappingForm, EditRegionAdMappingForm, EditRegionForm, EditRegionMappingForm, EditVariantForm, FilterForm, GoogleSheetForm, LoginForm, ProductMappingForm, RegionAdMappingForm, RegionMappingForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm, ProductForm, CountryForm, RegionForm, TikTokAccountForm, VariantForm, WarehouseForm, WarehouseProductForm
from . import mail
from flask_mail import Message
from flask_login import current_user, login_user, logout_user, login_required
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from flask_paginate import Pagination, get_page_args
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import logging
from google_auth_oauthlib.flow import Flow
import googleapiclient.discovery
from dotenv import load_dotenv


load_dotenv()


# Configurar el logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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

@main_bp.route('/authorize')
@login_required
def authorize():
    try:
        flow = Flow.from_client_secrets_file(
            'credentials.json',
            scopes=['https://www.googleapis.com/auth/spreadsheets.readonly'],
            redirect_uri=url_for('main_bp.oauth2callback', _external=True)
        )
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        session['state'] = state
        return redirect(authorization_url)
    except Exception as e:
        return str(e), 500

@main_bp.route('/oauth2callback')
@login_required
def oauth2callback():
    try:
        state = session['state']
        credentials_path = os.getenv('GOOGLE_CREDENTIALS_PATH', 'instance/credentials.json')
        flow = Flow.from_client_secrets_file(
            credentials_path, state=state,
            scopes=['https://www.googleapis.com/auth/spreadsheets.readonly'],
            redirect_uri=url_for('main_bp.oauth2callback', _external=True)
        )

        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)

        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)

        # Después de la autorización, redirige a una función que actualice los datos
        return redirect(url_for('main_bp.refresh_sheet_data'))
    except KeyError as e:
        return f"No state found in session: {str(e)}", 400
    except Exception as e:
        return f"An error occurred: {str(e)}", 400

@main_bp.route('/orders', methods=['GET', 'POST'])
@login_required
def orders():
    form = GoogleSheetForm()
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()

    if form.validate_on_submit():
        sheet_id = form.sheet_id.data
        sheet_name = form.sheet_name.data

        if linked_sheet:
            linked_sheet.sheet_id = sheet_id
            linked_sheet.sheet_name = sheet_name
        else:
            linked_sheet = LinkedSheet(user_id=current_user.id, sheet_id=sheet_id, sheet_name=sheet_name)
            db.session.add(linked_sheet)

        db.session.commit()
        return redirect(url_for('main_bp.authorize'))

    if not linked_sheet:
        return render_template('orders.html', form=form, data=None, headers=[], linked_sheet=None, mapped_data=None)

    # Mostrar los datos desde la base de datos
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page', per_page=50)
    sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).offset(offset).limit(per_page).all()
    total = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).count()

    data = [json.loads(item.data) for item in sheet_data_query]
    mapped_data = [json.loads(item.mapped_data) for item in sheet_data_query if item.mapped_data]  # Obtener datos mapeados
    headers = get_headers(linked_sheet.sheet_id)

    # Obtener los nombres de los productos para los mapeos
    product_mappings = ProductMapping.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
    product_mapping_dict = {mapping.original_value: mapping.mapped_value for mapping in product_mappings}

    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')

    return render_template('orders.html', form=form, data=data, headers=headers, pagination=pagination, linked_sheet=linked_sheet, mapped_data=mapped_data, product_mapping_dict=product_mapping_dict)

@main_bp.route('/unlink_sheet', methods=['POST'])
@login_required
def unlink_sheet():
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    if linked_sheet:
        # Eliminar datos relacionados en SheetData
        SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).delete()
        db.session.delete(linked_sheet)
        db.session.commit()
        flash('Sheet unlinked successfully.')

    return redirect(url_for('main_bp.orders'))

@main_bp.route('/refresh_sheet_data', methods=['GET', 'POST'])
@login_required
def refresh_sheet_data():
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    if not linked_sheet:
        return redirect(url_for('main_bp.orders'))

    if 'credentials' not in session:
        flash('Missing credentials. Please authorize the application.', 'danger')
        return redirect(url_for('main_bp.authorize'))

    try:
        update_sheet_data(linked_sheet.sheet_id, linked_sheet.sheet_name)
    except Exception as e:
        flash(f'Failed to refresh sheet data: {str(e)}', 'danger')
    else:
        flash('Sheet data refreshed successfully.', 'success')

    return redirect(url_for('main_bp.orders'))

def update_sheet_data(sheet_id, sheet_name):
    try:
        if 'credentials' not in session:
            raise RuntimeError("Missing credentials in session")

        credentials = google.oauth2.credentials.Credentials(**session['credentials'])
        service = build('sheets', 'v4', credentials=credentials, cache_discovery=False)
        range_name = f'{sheet_name}!A1:AF'

        result = service.spreadsheets().values().get(spreadsheetId=sheet_id, range=range_name).execute()
        values = result.get('values', [])

        if not values:
            raise RuntimeError("No data found in the sheet.")

        headers = values[0]  # Los headers son la primera fila
        rows = values[1:]  # Saltamos la primera fila para obtener los datos

        # Clear existing data for the sheet
        SheetData.query.filter_by(sheet_id=sheet_id).delete()

        # Fetch mappings
        product_mappings = ProductMapping.query.filter_by(user_id=current_user.id, sheet_id=sheet_id).all()
        country_mappings = CountryMapping.query.filter_by(user_id=current_user.id, sheet_id=sheet_id).all()
        region_mappings = RegionMapping.query.filter_by(user_id=current_user.id, sheet_id=sheet_id).all()

        product_mapping_dict = {m.original_value.lower(): m.mapped_value for m in product_mappings}
        country_mapping_dict = {m.original_value.lower(): m.mapped_value for m in country_mappings}
        region_mapping_dict = {m.original_value.lower(): m.mapped_value for m in region_mappings}

        # Process rows in chunks to handle large amounts of data
        for row in rows:
            if sum(1 for cell in row if cell) < 2:
                continue  # Skip rows with less than two non-empty cells

            # Ensure the row has the same number of columns as headers
            row += [''] * (len(headers) - len(row))

            unique_key = row[28]  # Adjust the index as needed
            if not unique_key:
                continue  # Skip rows without unique_key

            # Apply mappings without modifying original values
            mapped_row = row[:]
            for i, cell in enumerate(row):
                lower_cell = cell.lower()
                if lower_cell in product_mapping_dict:
                    mapped_row[i] = product_mapping_dict[lower_cell]
                elif lower_cell in country_mapping_dict:
                    mapped_row[i] = country_mapping_dict[lower_cell]
                elif lower_cell in region_mapping_dict:
                    mapped_row[i] = region_mapping_dict[lower_cell]

            # Insert new data
            new_data = SheetData(sheet_id=sheet_id, unique_key=unique_key, data=json.dumps(row), mapped_data=json.dumps(mapped_row))
            db.session.add(new_data)

        db.session.commit()

        # Store headers in a separate table or model if needed
        sheet_headers = SheetHeaders.query.filter_by(sheet_id=sheet_id).first()
        if sheet_headers:
            sheet_headers.headers = json.dumps(headers)
        else:
            sheet_headers = SheetHeaders(sheet_id=sheet_id, headers=json.dumps(headers))
            db.session.add(sheet_headers)
        db.session.commit()
    except Exception as e:
        raise RuntimeError(f"Failed to update sheet data: {e}")


    
def get_headers(sheet_id):
    headers_record = SheetHeaders.query.filter_by(sheet_id=sheet_id).first()
    if headers_record:
        return json.loads(headers_record.headers)
    return []


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }



@main_bp.route('/delete_linked_sheet', methods=['POST'])
@login_required
def delete_linked_sheet():
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    if linked_sheet:
        db.session.delete(linked_sheet)
        db.session.commit()
        flash('Linked sheet deleted successfully.')
    return redirect(url_for('main_bp.orders'))


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

@main_bp.route('/product_mappings', methods=['GET', 'POST'])
@login_required
def manage_product_mappings():
    form = ProductMappingForm()

    # Obtener todos los productos y variantes del usuario actual
    products = Product.query.filter_by(user_id=current_user.id).order_by(Product.name).all()
    all_variants = Variant.query.join(Product).filter(Product.user_id == current_user.id).all()

    # Construir opciones para el campo de selección del formulario
    product_variants = [(f'{variant.product.id}-{variant.id}', f'{variant.product.name} - {variant.name}') for variant in all_variants]
    product_variants += [(f'{product.id}-None', f'{product.name}') for product in products]

    form.product_id.choices = product_variants

    # Obtener encabezados de Google Sheets
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    headers = get_headers(linked_sheet.sheet_id) if linked_sheet else []
    form.sheet_header.choices = [(header, header) for header in headers]

    if form.validate_on_submit():
        try:
            product_variant_id = form.product_id.data.split('-')
            product_id = int(product_variant_id[0])
            variant_id = int(product_variant_id[1]) if product_variant_id[1] != 'None' else None

            product_name = dict(form.product_id.choices).get(form.product_id.data)

            for sheet_product in form.sheet_products.data:
                mapping = ProductMapping(
                    user_id=current_user.id,
                    sheet_id=linked_sheet.sheet_id,
                    product_id=product_id,
                    variant_id=variant_id,
                    original_value=sheet_product,
                    mapped_value=product_name
                )
                db.session.add(mapping)
            db.session.commit()
            flash('Product mapped successfully!', 'success')
            return redirect(url_for('main_bp.manage_product_mappings'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error mapping product: {str(e)}', 'danger')

    # Agrupar mapeos por producto
    mappings = ProductMapping.query.filter_by(user_id=current_user.id).all()
    grouped_mappings = {}
    for mapping in mappings:
        if mapping.product_id not in grouped_mappings:
            grouped_mappings[mapping.product_id] = {
                'product': mapping.product,
                'variant': mapping.variant,
                'original_values': [],
                'id': mapping.id
            }
        grouped_mappings[mapping.product_id]['original_values'].append(mapping.original_value)

    return render_template('product_mappings.html', form=form, grouped_mappings=grouped_mappings)


@main_bp.route('/get_sheet_products/<sheet_header>', methods=['GET'])
@login_required
def get_sheet_products(sheet_header):
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    if not linked_sheet:
        return jsonify({'error': 'No linked sheet found'}), 404
    
    sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
    products_from_sheet = set()
    headers = get_headers(linked_sheet.sheet_id)
    
    if sheet_header in headers:
        header_index = headers.index(sheet_header)
    else:
        return jsonify({'error': 'Sheet header not found'}), 404

    for item in sheet_data_query:
        row = json.loads(item.data)
        if header_index < len(row):
            products_from_sheet.add(row[header_index])

    # Obtener productos ya mapeados para excluirlos
    mapped_original_values = {mapping.original_value for mapping in ProductMapping.query.filter_by(sheet_id=linked_sheet.sheet_id).all()}
    products_to_map = products_from_sheet - mapped_original_values

    return jsonify({'products': sorted(list(products_to_map))})

@main_bp.route('/edit_product_mapping/<int:mapping_id>', methods=['GET', 'POST'])
@login_required
def edit_product_mapping(mapping_id):
    mapping = ProductMapping.query.get_or_404(mapping_id)
    form = EditProductMappingForm()

    # Obtener todos los productos y variantes del usuario actual
    products = Product.query.filter_by(user_id=current_user.id).all()
    all_variants = Variant.query.join(Product).filter(Product.user_id == current_user.id).all()

    # Construir opciones para el campo de selección del formulario
    product_variants = [(f'{variant.product.id}-{variant.id}', f'{variant.product.name} - {variant.name}') for variant in all_variants]

    # Si un producto tiene variantes, no agregarlo a la lista de productos
    products_without_variants = [product for product in products if not any(variant.product_id == product.id for variant in all_variants)]
    product_variants += [(f'{product.id}-None', f'{product.name}') for product in products_without_variants]

    form.product_id.choices = product_variants

    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    headers = get_headers(linked_sheet.sheet_id) if linked_sheet else []
    form.sheet_header.choices = [(header, header) for header in headers]

    # Pre-cargar los datos existentes
    if request.method == 'GET':
        form.product_id.data = f'{mapping.product_id}-{mapping.variant_id}' if mapping.variant_id else f'{mapping.product_id}-None'
        sheet_header = form.sheet_header.data
        sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
        products_from_sheet = set()

        # Obtener los productos ya mapeados
        existing_mappings = ProductMapping.query.filter_by(product_id=mapping.product_id, sheet_id=linked_sheet.sheet_id).all()
        for m in existing_mappings:
            products_from_sheet.add(m.original_value)

        # Agregar productos del encabezado seleccionado
        if sheet_header:
            header_index = headers.index(sheet_header)
            for item in sheet_data_query:
                row = json.loads(item.data)
                if header_index < len(row):
                    products_from_sheet.add(row[header_index])

        form.sheet_products.choices = [(product, product) for product in products_from_sheet]
        form.sheet_products.data = [m.original_value for m in existing_mappings]

    if request.method == 'POST':
        # Obtener los productos del encabezado seleccionado para actualizar las opciones antes de validar
        sheet_header = form.sheet_header.data
        sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
        products_from_sheet = set()
        header_index = headers.index(sheet_header)
        for item in sheet_data_query:
            row = json.loads(item.data)
            if header_index < len(row):
                products_from_sheet.add(row[header_index])
        form.sheet_products.choices = [(product, product) for product in products_from_sheet]

        if form.validate_on_submit():
            try:
                product_variant_id = form.product_id.data.split('-')
                product_id = int(product_variant_id[0])
                variant_id = int(product_variant_id[1]) if product_variant_id[1] != 'None' else None

                # Eliminar mapeos existentes y agregar nuevos mapeos
                ProductMapping.query.filter_by(product_id=product_id, sheet_id=linked_sheet.sheet_id).delete()
                db.session.commit()

                for product_name in form.sheet_products.data:
                    new_mapping = ProductMapping(
                        user_id=current_user.id,
                        sheet_id=linked_sheet.sheet_id,
                        product_id=product_id,
                        variant_id=variant_id,
                        original_value=product_name,
                        mapped_value=dict(form.product_id.choices).get(form.product_id.data)
                    )
                    db.session.add(new_mapping)

                db.session.commit()
                flash('Product mapping updated successfully!')
                return redirect(url_for('main_bp.edit_product_mapping', mapping_id=mapping_id))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating product mapping: {str(e)}', 'danger')

    all_mappings = ProductMapping.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
    return render_template('edit_product_mapping.html', form=form, all_mappings=all_mappings, mapping_id=mapping_id)

# Ruta para eliminar un mapeo completo
@main_bp.route('/delete_product_mapping/<int:product_id>', methods=['POST'])
@login_required
def delete_product_mapping(product_id):
    mappings = ProductMapping.query.filter_by(product_id=product_id).all()
    for mapping in mappings:
        db.session.delete(mapping)
    db.session.commit()
    flash('Product mapping deleted successfully!', 'success')
    return redirect(url_for('main_bp.manage_product_mappings'))

@main_bp.route('/delete_individual_mapping/<int:mapping_id>', methods=['POST'])
@login_required
def delete_individual_mapping(mapping_id):
    mapping = ProductMapping.query.get_or_404(mapping_id)
    product_id = mapping.product_id  # Obtener el product_id antes de eliminar el mapeo
    try:
        db.session.delete(mapping)
        db.session.commit()
        flash('Individual product mapping deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting individual product mapping: {str(e)}', 'danger')
    return redirect(url_for('main_bp.edit_product_mapping', mapping_id=mapping_id))


@main_bp.route('/country_mappings', methods=['GET', 'POST'])
@login_required
def manage_country_mappings():
    form = CountryMappingForm()

    # Obtener todos los países del usuario actual
    countries = Country.query.filter_by(user_id=current_user.id).order_by(Country.name).all()

    # Obtener países ya mapeados
    mapped_country_ids = [mapping.country_id for mapping in CountryMapping.query.filter_by(user_id=current_user.id).all()]

    # Filtrar países no mapeados
    unmapped_countries = [country for country in countries if country.id not in mapped_country_ids]

    # Construir opciones para el campo de selección del formulario
    form.country_id.choices = [(country.id, country.name) for country in unmapped_countries]

    # Obtener encabezados de Google Sheets
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    headers = get_headers(linked_sheet.sheet_id) if linked_sheet else []
    form.sheet_header.choices = [(header, header) for header in headers]

    # Obtener países ya mapeados para excluirlos de la lista
    if linked_sheet:
        mapped_original_values = set(mapping.original_value for mapping in CountryMapping.query.filter_by(sheet_id=linked_sheet.sheet_id).all())

    # Obtener países relacionados con el encabezado seleccionado y excluir los mapeados
    if form.sheet_header.data:
        sheet_header = form.sheet_header.data
        sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
        countries_from_sheet = set()
        header_index = headers.index(sheet_header)
        for item in sheet_data_query:
            row = json.loads(item.data)
            if header_index < len(row):
                countries_from_sheet.add(row[header_index])
        # Excluir países ya mapeados
        countries_to_map = countries_from_sheet - mapped_original_values
        form.sheet_countries.choices = [(country, country) for country in countries_to_map]

    if form.validate_on_submit():
        try:
            country_id = form.country_id.data
            country_name = dict(form.country_id.choices).get(int(form.country_id.data))
            
            for sheet_country in form.sheet_countries.data:
                mapping = CountryMapping(
                    user_id=current_user.id,
                    sheet_id=linked_sheet.sheet_id,
                    country_id=country_id,
                    original_value=sheet_country,
                    mapped_value=country_name
                )
                db.session.add(mapping)
            db.session.commit()
            flash('Country mapped successfully!', 'success')
            return redirect(url_for('main_bp.manage_country_mappings'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error mapping country: {str(e)}', 'danger')

    # Agrupar mapeos por país
    mappings = CountryMapping.query.filter_by(user_id=current_user.id).all()
    grouped_mappings = {}
    for mapping in mappings:
        if mapping.country_id not in grouped_mappings:
            grouped_mappings[mapping.country_id] = {
                'country': mapping.country,
                'sheet_id': mapping.sheet_id,
                'original_values': [],
                'id': mapping.id
            }
        grouped_mappings[mapping.country_id]['original_values'].append(mapping.original_value)

    return render_template('country_mappings.html', form=form, grouped_mappings=grouped_mappings)

@main_bp.route('/get_sheet_countries/<sheet_header>', methods=['GET'])
@login_required
def get_sheet_countries(sheet_header):
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    if not linked_sheet:
        return jsonify({'error': 'No linked sheet found'}), 404
    
    sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
    countries_from_sheet = set()
    headers = get_headers(linked_sheet.sheet_id)
    
    if sheet_header in headers:
        header_index = headers.index(sheet_header)
    else:
        return jsonify({'error': 'Sheet header not found'}), 404

    for item in sheet_data_query:
        row = json.loads(item.data)
        if header_index < len(row):
            countries_from_sheet.add(row[header_index])
    
    return jsonify({'countries': sorted(list(countries_from_sheet))})

@main_bp.route('/edit_country_mapping/<int:mapping_id>', methods=['GET', 'POST'])
@login_required
def edit_country_mapping(mapping_id):
    mapping = CountryMapping.query.get_or_404(mapping_id)
    form = EditCountryMappingForm()

    # Preparar las opciones del formulario
    countries = Country.query.filter_by(user_id=current_user.id).all()

    # Construir opciones para el campo de selección del formulario
    form.country_id.choices = [(country.id, country.name) for country in countries]

    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    headers = get_headers(linked_sheet.sheet_id) if linked_sheet else []
    form.sheet_header.choices = [(header, header) for header in headers]

    # Inicializar existing_mappings para asegurar que esté definido
    existing_mappings = []

    if request.method == 'GET':
        # Pre-cargar los datos existentes
        form.country_id.data = mapping.country_id
        form.sheet_header.data = headers[0] if headers else None

        # Obtener los países del encabezado seleccionado
        if headers:
            sheet_header = headers[0]
            sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
            countries_from_sheet = set()
            header_index = headers.index(sheet_header)
            for item in sheet_data_query:
                row = json.loads(item.data)
                if header_index < len(row):
                    countries_from_sheet.add(row[header_index])
            form.sheet_countries.choices = [(country, country) for country in countries_from_sheet]
            existing_mappings = CountryMapping.query.filter_by(country_id=mapping.country_id, sheet_id=linked_sheet.sheet_id).all()
            form.sheet_countries.data = [m.original_value for m in existing_mappings]

        # Logs para verificar los datos cargados
        logger.debug("GET request: Loaded existing mappings: %s", form.sheet_countries.data)
        logger.debug("GET request: Form data: %s", form.data)

    if request.method == 'POST':
        # Obtener los países del encabezado seleccionado para actualizar las opciones antes de validar
        sheet_header = form.sheet_header.data
        sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
        countries_from_sheet = set()
        header_index = headers.index(sheet_header)
        for item in sheet_data_query:
            row = json.loads(item.data)
            if header_index < len(row):
                countries_from_sheet.add(row[header_index])
        form.sheet_countries.choices = [(country, country) for country in countries_from_sheet]

        if form.validate_on_submit():
            try:
                country_id = form.country_id.data

                # Obtener mapeos existentes
                existing_mappings = CountryMapping.query.filter_by(country_id=country_id, sheet_id=linked_sheet.sheet_id).all()

                # Agregar nuevos mapeos sin eliminar los anteriores
                existing_values = set(m.original_value for m in existing_mappings)
                new_values = set(form.sheet_countries.data)
                values_to_add = new_values - existing_values

                for country_name in values_to_add:
                    new_mapping = CountryMapping(
                        user_id=current_user.id,
                        sheet_id=linked_sheet.sheet_id,
                        country_id=country_id,
                        original_value=country_name,
                        mapped_value=dict(form.country_id.choices).get(int(form.country_id.data))
                    )
                    db.session.add(new_mapping)
                    logger.debug("POST request: Added new mapping: %s", new_mapping)

                db.session.commit()
                logger.debug("POST request: Database commit successful, redirecting...")
                flash('Country mapping updated successfully!')
                return redirect(url_for('main_bp.manage_country_mappings'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating country mapping: {str(e)}', 'danger')
                logger.error(f'Error updating country mapping: {str(e)}')
        else:
            logger.debug("POST request: Form validation failed with errors: %s", form.errors)

    return render_template('edit_country_mapping.html', form=form, mappings=existing_mappings)

@main_bp.route('/delete_country_mapping/<int:mapping_id>', methods=['POST'])
@login_required
def delete_country_mapping(mapping_id):
    mapping = CountryMapping.query.get_or_404(mapping_id)
    db.session.delete(mapping)
    db.session.commit()
    flash('Country mapping deleted successfully!')
    return redirect(url_for('main_bp.manage_country_mappings'))

@main_bp.route('/region_mappings', methods=['GET', 'POST'])
@login_required
def manage_region_mappings():
    form = RegionMappingForm()

    # Obtener todas las regiones del usuario actual
    regions = Region.query.filter_by(user_id=current_user.id).order_by(Region.name).all()

    # Obtener regiones ya mapeadas
    mapped_region_ids = [mapping.region_id for mapping in RegionMapping.query.filter_by(user_id=current_user.id).all()]

    # Filtrar regiones no mapeadas
    unmapped_regions = [region for region in regions if region.id not in mapped_region_ids]

    # Construir opciones para el campo de selección del formulario
    form.region_id.choices = [(region.id, region.name) for region in unmapped_regions]

    # Obtener encabezados de Google Sheets
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    headers = get_headers(linked_sheet.sheet_id) if linked_sheet else []
    form.sheet_header.choices = [(header, header) for header in headers]

    # Obtener regiones ya mapeadas para excluirlas de la lista
    if linked_sheet:
        mapped_original_values = set(mapping.original_value for mapping in RegionMapping.query.filter_by(sheet_id=linked_sheet.sheet_id).all())

    # Obtener regiones relacionadas con el encabezado seleccionado y excluir las mapeadas
    if form.sheet_header.data:
        sheet_header = form.sheet_header.data
        sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
        regions_from_sheet = set()
        header_index = headers.index(sheet_header)
        for item in sheet_data_query:
            row = json.loads(item.data)
            if header_index < len(row):
                regions_from_sheet.add(row[header_index])
        # Excluir regiones ya mapeadas
        regions_to_map = regions_from_sheet - mapped_original_values
        form.sheet_regions.choices = [(region, region) for region in regions_to_map]

    if form.validate_on_submit():
        try:
            region_id = form.region_id.data
            region_name = dict(form.region_id.choices).get(int(form.region_id.data))
            
            for sheet_region in form.sheet_regions.data:
                mapping = RegionMapping(
                    user_id=current_user.id,
                    sheet_id=linked_sheet.sheet_id,
                    region_id=region_id,
                    original_value=sheet_region,
                    mapped_value=region_name
                )
                db.session.add(mapping)
            db.session.commit()
            flash('Region mapped successfully!', 'success')
            return redirect(url_for('main_bp.manage_region_mappings'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error mapping region: {str(e)}', 'danger')

    # Agrupar mapeos por región
    mappings = RegionMapping.query.filter_by(user_id=current_user.id).all()
    grouped_mappings = {}
    for mapping in mappings:
        if mapping.region_id not in grouped_mappings:
            grouped_mappings[mapping.region_id] = {
                'region': mapping.region,
                'sheet_id': mapping.sheet_id,
                'original_values': [],
                'id': mapping.id
            }
        grouped_mappings[mapping.region_id]['original_values'].append(mapping.original_value)

    return render_template('region_mappings.html', form=form, grouped_mappings=grouped_mappings)

@main_bp.route('/get_sheet_regions/<sheet_header>', methods=['GET'])
@login_required
def get_sheet_regions(sheet_header):
    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    if not linked_sheet:
        return jsonify({'error': 'No linked sheet found'}), 404
    
    sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
    regions_from_sheet = set()
    headers = get_headers(linked_sheet.sheet_id)
    
    if sheet_header in headers:
        header_index = headers.index(sheet_header)
    else:
        return jsonify({'error': 'Sheet header not found'}), 404

    for item in sheet_data_query:
        row = json.loads(item.data)
        if header_index < len(row):
            regions_from_sheet.add(row[header_index])
    
    return jsonify({'regions': sorted(list(regions_from_sheet))})

@main_bp.route('/edit_region_mapping/<int:mapping_id>', methods=['GET', 'POST'])
@login_required
def edit_region_mapping(mapping_id):
    mapping = RegionMapping.query.get_or_404(mapping_id)
    form = EditRegionMappingForm()

    # Preparar las opciones del formulario
    regions = Region.query.filter_by(user_id=current_user.id).all()

    # Construir opciones para el campo de selección del formulario
    form.region_id.choices = [(region.id, region.name) for region in regions]

    linked_sheet = LinkedSheet.query.filter_by(user_id=current_user.id).first()
    headers = get_headers(linked_sheet.sheet_id) if linked_sheet else []
    form.sheet_header.choices = [(header, header) for header in headers]

    # Inicializar existing_mappings para asegurar que esté definido
    existing_mappings = []

    if request.method == 'GET':
        # Pre-cargar los datos existentes
        form.region_id.data = mapping.region_id
        form.sheet_header.data = headers[0] if headers else None

        # Obtener las regiones del encabezado seleccionado
        if headers:
            sheet_header = headers[0]
            sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
            regions_from_sheet = set()
            header_index = headers.index(sheet_header)
            for item in sheet_data_query:
                row = json.loads(item.data)
                if header_index < len(row):
                    regions_from_sheet.add(row[header_index])
            form.sheet_regions.choices = [(region, region) for region in regions_from_sheet]
            existing_mappings = RegionMapping.query.filter_by(region_id=mapping.region_id, sheet_id=linked_sheet.sheet_id).all()
            form.sheet_regions.data = [m.original_value for m in existing_mappings]

        # Logs para verificar los datos cargados
        logger.debug("GET request: Loaded existing mappings: %s", form.sheet_regions.data)
        logger.debug("GET request: Form data: %s", form.data)

    if request.method == 'POST':
        # Obtener las regiones del encabezado seleccionado para actualizar las opciones antes de validar
        sheet_header = form.sheet_header.data
        sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
        regions_from_sheet = set()
        header_index = headers.index(sheet_header)
        for item in sheet_data_query:
            row = json.loads(item.data)
            if header_index < len(row):
                regions_from_sheet.add(row[header_index])
        form.sheet_regions.choices = [(region, region) for region in regions_from_sheet]

        if form.validate_on_submit():
            try:
                region_id = form.region_id.data

                # Obtener mapeos existentes
                existing_mappings = RegionMapping.query.filter_by(region_id=region_id, sheet_id=linked_sheet.sheet_id).all()

                # Agregar nuevos mapeos sin eliminar los anteriores
                existing_values = set(m.original_value for m in existing_mappings)
                new_values = set(form.sheet_regions.data)
                values_to_add = new_values - existing_values

                for region_name in values_to_add:
                    new_mapping = RegionMapping(
                        user_id=current_user.id,
                        sheet_id=linked_sheet.sheet_id,
                        region_id=region_id,
                        original_value=region_name,
                        mapped_value=dict(form.region_id.choices).get(int(form.region_id.data))
                    )
                    db.session.add(new_mapping)
                    logger.debug("POST request: Added new mapping: %s", new_mapping)

                db.session.commit()
                logger.debug("POST request: Database commit successful, redirecting...")
                flash('Region mapping updated successfully!')
                return redirect(url_for('main_bp.manage_region_mappings'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating region mapping: {str(e)}', 'danger')
                logger.error(f'Error updating region mapping: {str(e)}')
        else:
            logger.debug("POST request: Form validation failed with errors: %s", form.errors)

    return render_template('edit_region_mapping.html', form=form, mappings=existing_mappings)

@main_bp.route('/delete_region_mapping/<int:mapping_id>', methods=['POST'])
@login_required
def delete_region_mapping(mapping_id):
    mapping = RegionMapping.query.get_or_404(mapping_id)
    db.session.delete(mapping)
    db.session.commit()
    flash('Region mapping deleted successfully!')
    return redirect(url_for('main_bp.manage_region_mappings'))

@main_bp.route('/ads', methods=['GET', 'POST'])
@login_required
def ads():
    user_id = current_user.id
    accounts = Account.query.filter_by(user_id=user_id).all()
    delete_form = DeleteAccountForm()
    form = DateRangeForm()

    if form.validate_on_submit():
        start_date_str = form.start_date.data
        end_date_str = form.end_date.data

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

            for account in accounts:
                if account.account_type == 'facebook':
                    update_facebook_data(start_date_str, end_date_str, account.token, account.ad_accounts, user_id)
                elif account.account_type == 'tiktok':
                    update_tiktok_data(start_date_str, end_date_str, account.token, account.ad_accounts, user_id)

            flash('Datos actualizados correctamente.', 'success')
        except ValueError as e:
            flash('Formato de fecha inválido. Por favor, usa el formato YYYY-MM-DD.', 'error')

    campaigns = CampaignData.query.filter_by(user_id=user_id).all()
    headers = ['Fecha', 'Nombre de Campaña', 'País (Facebook/TikTok)', 'Región (Facebook/TikTok)', 'Currency', 'Ad Spend', 'Plataforma']
    headers_mapped = ['Fecha', 'Nombre de Producto', 'País Mapeado', 'Región Mapeada', 'Currency', 'Ad Spend', 'Plataforma']

    data = []
    mapped_data = []

    # Obtener todos los mapeos de anuncios
    ad_mappings = AdMapping.query.filter_by(user_id=user_id).all()
    mapping_dict = {mapping.keyword: mapping.product.name for mapping in ad_mappings}

    # Obtener todos los mapeos de países
    country_mappings = CountryAdMapping.query.filter_by(user_id=user_id).all()
    country_mapping_dict = {mapping.ad_country: mapping.country.name for mapping in country_mappings}

    # Obtener todos los mapeos de regiones
    region_mappings = RegionAdMapping.query.filter_by(user_id=user_id).all()
    region_mapping_dict = {mapping.ad_region: mapping.region.name for mapping in region_mappings}

    for campaign in campaigns:
        product_name = 'No mapeado'
        for keyword, product in mapping_dict.items():
            if keyword.lower() in campaign.campaign_name.lower():
                product_name = product
                break

        country_mapped = country_mapping_dict.get(campaign.country_facebook, campaign.country_facebook)
        region_mapped = region_mapping_dict.get(campaign.region_facebook, campaign.region_facebook)

        data.append([
            campaign.date,
            campaign.campaign_name,
            campaign.country_facebook,
            campaign.region_facebook,
            campaign.currency,
            campaign.spend,
            campaign.platform
        ])
        
        mapped_data.append([
            campaign.date,
            product_name,
            country_mapped,
            region_mapped,
            campaign.currency,
            campaign.spend,
            campaign.platform,
        ])

    return render_template('ads.html', accounts=accounts, form=form, headers=headers, headers_mapped=headers_mapped, data=data, mapped_data=mapped_data, delete_form=delete_form)

def get_facebook_account_currency(token, ad_account_id):
    base_url = "https://graph.facebook.com/v18.0"
    endpoint = f"{base_url}/{ad_account_id}"
    params = {
        'access_token': token,
        'fields': 'currency'
    }

    try:
        response = requests.get(endpoint, params=params)
        data = response.json()
        if 'error' in data:
            print(f"Error retrieving currency for account {ad_account_id}: {data['error']['message']}")
            return 'USD'
        return data.get('currency', 'USD')
    except requests.RequestException as e:
        print(f"Error in API request for account {ad_account_id}: {e}")
        return 'USD'

def update_facebook_data(start_date, end_date, token, ad_accounts, user_id):
    start_date_utc = datetime.strptime(start_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
    end_date_utc = datetime.strptime(end_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)

    start_date_formatted = start_date_utc.strftime('%Y-%m-%d')
    end_date_formatted = end_date_utc.strftime('%Y-%m-%d')

    base_url = "https://graph.facebook.com/v18.0"
    fields = 'campaign_name,spend,date_start'
    limit = 5000

    for ad_account in ad_accounts.split(','):
        currency = get_facebook_account_currency(token, ad_account)
        endpoint = f"{base_url}/{ad_account}/insights"
        params = {
            'access_token': token,
            'level': 'campaign',
            'fields': fields,
            'breakdowns': 'country,region',
            'time_range': json.dumps({'since': start_date_formatted, 'until': end_date_formatted}),
            'time_increment': 1,
            'limit': limit
        }

        try:
            response = requests.get(endpoint, params=params)
            data = response.json()
            if 'error' in data:
                print(f"Error in API for {ad_account}: {data['error']['message']}")
            else:
                if 'data' in data:
                    for ad in data['data']:
                        campaign_name = ad.get('campaign_name', 'Unspecified')
                        spend = float(ad.get('spend', '0'))
                        country = ad.get('country', 'Unknown')
                        region = ad.get('region', 'Unknown')
                        date_str = ad.get('date_start', 'Date not available')
                        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()  # Convertir a objeto date

                        campaign_data = {
                            'campaign_name': campaign_name,
                            'spend': spend,
                            'currency': currency,
                            'country_facebook': country,
                            'region_facebook': region,
                            'country_real': map_country(country),  # Usar la función map_country
                            'region_real': map_region(region),    # Usar la función map_region
                            'date': date_obj,  # Usar el objeto date
                            'account_id': ad_account,
                            'platform': 'facebook',
                            'user_id': user_id
                        }
                        insert_or_update_campaign_data(campaign_data)
        except requests.RequestException as e:
            print(f"Error in API request for account {ad_account}: {e}")

def insert_or_update_campaign_data(campaign_data):
    existing_data = CampaignData.query.filter_by(
        campaign_name=campaign_data['campaign_name'],
        date=campaign_data['date'],
        country_facebook=campaign_data['country_facebook'],
        region_facebook=campaign_data['region_facebook'],
        account_id=campaign_data['account_id'],
        platform=campaign_data['platform']
    ).first()

    if existing_data:
        if existing_data.spend != campaign_data['spend']:
            existing_data.spend = campaign_data['spend']
            db.session.commit()
    else:
        new_campaign_data = CampaignData(**campaign_data)
        db.session.add(new_campaign_data)
        db.session.commit()


def map_country(country):
    # Define aquí la lógica para mapear el país
    pass

def map_region(region):
    # Define aquí la lógica para mapear la región
    pass

def update_tiktok_data(start_date, end_date, token, advertiser_id, user_id):
    base_url = "https://business-api.tiktok.com/open_api/v1.3"
    endpoint = f"{base_url}/report/integrated/get/"

    headers = {
        'Access-Token': token,
        'Content-Type': 'application/json'
    }

    params = {
        'advertiser_id': advertiser_id,
        'report_type': 'AUDIENCE',
        'dimensions': '["campaign_id", "province_id", "stat_time_day"]',
        'metrics': '["spend", "campaign_name", "currency"]',
        'start_date': start_date,
        'end_date': end_date,
        'data_level': 'AUCTION_CAMPAIGN',
        'page': 1,
        'page_size': 1000
    }

    all_records = []

    while True:
        try:
            response = requests.get(endpoint, headers=headers, params=params)
            logger.debug(f"API response status code: {response.status_code}")
            logger.debug(f"API response data: {response.json()}")

            if response.status_code == 404:
                logger.error("Endpoint not found. Please check the URL and parameters.")
                return

            data = response.json()
            if 'code' in data and data['code'] == 0:
                all_records.extend(data['data']['list'])
                if not data['data']['list']:
                    logger.debug("No data found for the given date range and parameters.")
                    return

                if data['data']['page_info']['total_page'] <= params['page']:
                    break
                else:
                    params['page'] += 1
            else:
                logger.error(f"Error in API response: {data}")
                break
        except requests.RequestException as e:
            logger.error(f"Error in API request: {e}")
            break
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON response: {e}")
            break

    for record in all_records:
        campaign_name = record['metrics'].get('campaign_name', 'Unspecified')
        spend = float(record['metrics'].get('spend', '0'))
        currency = record['metrics'].get('currency', 'USD')
        date_str = record['dimensions'].get('stat_time_day', 'Date not available')
        province_id = record['dimensions'].get('province_id', 'Unspecified')

        # Convertir la fecha a un objeto datetime.date
        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S').date()
            logger.debug(f"Converted date: {date_obj}")
        except ValueError as e:
            logger.error(f"Error converting date: {e}")
            continue

        country_real = map_country(province_id)
        region_real = map_region(province_id)

        campaign_data = {
            'campaign_name': campaign_name,
            'spend': spend,
            'currency': currency,
            'country_facebook': province_id,
            'region_facebook': province_id,
            'country_real': country_real,
            'region_real': region_real,
            'date': date_obj,  # Usar el objeto date
            'account_id': advertiser_id,
            'platform': 'tiktok',
            'user_id': user_id
        }

        insert_or_update_campaign_data(campaign_data)

def insert_or_update_campaign_data(campaign_data):
    try:
        existing_data = CampaignData.query.filter_by(
            campaign_name=campaign_data['campaign_name'],
            date=campaign_data['date'],
            country_facebook=campaign_data['country_facebook'],
            region_facebook=campaign_data['region_facebook'],
            account_id=campaign_data['account_id'],
            platform=campaign_data['platform']
        ).first()

        if existing_data:
            if existing_data.spend != campaign_data['spend']:
                existing_data.spend = campaign_data['spend']
                db.session.commit()
                logger.debug(f"Updated existing campaign data: {existing_data}")
        else:
            new_campaign_data = CampaignData(**campaign_data)
            db.session.add(new_campaign_data)
            db.session.commit()
            logger.debug(f"Inserted new campaign data: {new_campaign_data}")
    except Exception as e:
        logger.error(f"Error inserting or updating campaign data: {e}")
        db.session.rollback()



@main_bp.route('/add_facebook_account', methods=['GET', 'POST'])
@login_required
def add_facebook_account():
    form = AccountForm()
    if form.validate_on_submit():
        ad_accounts_list = [entry.data for entry in form.ad_accounts if entry.data]
        current_app.logger.debug(f'Ad accounts list from form: {ad_accounts_list}')
        
        new_account = Account(
            user_id=current_user.id,
            name=form.name.data,
            account_type='facebook',
            token=form.token.data,
            ad_accounts=','.join(ad_accounts_list),
            linked_date=datetime.utcnow()
        )
        db.session.add(new_account)
        db.session.commit()
        flash('Cuenta de Facebook vinculada con éxito.', 'success')
        return redirect(url_for('main_bp.ads'))
    return render_template('add_facebook_account.html', form=form)



@main_bp.route('/add_tiktok_account', methods=['GET', 'POST'])
@login_required
def add_tiktok_account():
    form = TikTokAccountForm()
    if form.validate_on_submit():
        new_account = Account(
            user_id=current_user.id,
            name=form.name.data,
            account_type='tiktok',
            token=form.access_token.data,
            ad_accounts=form.advertiser_id.data,
            linked_date=datetime.utcnow()
        )
        db.session.add(new_account)
        db.session.commit()
        flash('Cuenta de TikTok vinculada con éxito.', 'success')
        return redirect(url_for('main_bp.ads'))
    return render_template('add_tiktok_account.html', form=form)

@main_bp.route('/edit_account/<int:account_id>', methods=['GET', 'POST'])
@login_required
def edit_account(account_id):
    account = Account.query.get_or_404(account_id)
    form = AccountForm(obj=account)

    if request.method == 'GET' or not form.is_submitted():
        while len(form.ad_accounts.entries) > 0:
            form.ad_accounts.pop_entry()

        ad_accounts_list = account.ad_accounts.split(',') if account.ad_accounts else []
        for ad_id in ad_accounts_list:
            form.ad_accounts.append_entry({'ad_account_id': ad_id})

    if form.validate_on_submit():
        account.name = form.name.data
        account.token = form.token.data
        account.account_type = form.account_type.data

        new_ad_accounts = [entry.data['ad_account_id'] for entry in form.ad_accounts.entries if entry.data['ad_account_id']]
        account.ad_accounts = ','.join(new_ad_accounts)
        
        db.session.commit()
        flash('Cuenta actualizada con éxito.', 'success')
        return redirect(url_for('main_bp.ads'))  # Redirige a la página de anuncios (ads)
    else:
        flash_errors(form)

    return render_template('edit_facebook_account.html', form=form, account=account)

def flash_errors(form):
    """Flash all errors for a form."""
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"Error en el campo {getattr(form, field).label.text}: {error}", 'error')


@main_bp.route('/link_accounts')
@login_required
def link_accounts():
    user_id = current_user.id
    accounts = Account.query.filter_by(user_id=user_id).all()
    form = DeleteAccountForm()
    return render_template('link_accounts.html', accounts=accounts, form=form)


@main_bp.route('/delete_account/<int:account_id>', methods=['POST'])
@login_required
def delete_account(account_id):
    account = Account.query.get_or_404(account_id)
    db.session.delete(account)
    db.session.commit()
    flash('Cuenta eliminada con éxito.', 'success')
    return redirect(url_for('main_bp.ads'))

@main_bp.route('/ad_mappings', methods=['GET', 'POST'])
@login_required
def manage_ad_mappings():
    form = AdMappingForm()

    # Obtener todos los productos del usuario actual que no están mapeados
    mapped_product_ids = [mapping.product_id for mapping in AdMapping.query.filter_by(user_id=current_user.id).all()]
    products = Product.query.filter(Product.user_id == current_user.id, Product.id.notin_(mapped_product_ids)).order_by(Product.name).all()
    form.product_id.choices = [(product.id, product.name) for product in products]

    if form.validate_on_submit():
        try:
            for keyword_form in form.keywords:
                ad_mapping = AdMapping(
                    user_id=current_user.id,
                    product_id=form.product_id.data,
                    keyword=keyword_form.keyword.data,
                )
                db.session.add(ad_mapping)
            db.session.commit()
            flash('Ad mapped successfully!', 'success')
            return redirect(url_for('main_bp.manage_ad_mappings'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error mapping ad: {str(e)}', 'danger')

    mappings = AdMapping.query.filter_by(user_id=current_user.id).all()
    grouped_mappings = {}
    for mapping in mappings:
        if mapping.product_id not in grouped_mappings:
            grouped_mappings[mapping.product_id] = {
                'product_id': mapping.product_id,
                'product': mapping.product.name,
                'keywords': []
            }
        grouped_mappings[mapping.product_id]['keywords'].append(mapping.keyword)

    return render_template('ad_mappings.html', form=form, grouped_mappings=grouped_mappings)

@main_bp.route('/edit_ad_mapping/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_ad_mapping(product_id):
    mappings = AdMapping.query.filter_by(user_id=current_user.id, product_id=product_id).all()
    if not mappings:
        flash('No mappings found for the selected product.', 'danger')
        return redirect(url_for('main_bp.manage_ad_mappings'))

    form = AdMappingForm()
    products = Product.query.filter_by(user_id=current_user.id).all()
    form.product_id.choices = [(product.id, product.name) for product in products]
    form.product_id.data = product_id

    if form.validate_on_submit():
        try:
            AdMapping.query.filter_by(user_id=current_user.id, product_id=product_id).delete()
            for keyword_form in form.keywords:
                ad_mapping = AdMapping(
                    user_id=current_user.id,
                    product_id=form.product_id.data,
                    keyword=keyword_form.data['keyword'],
                )
                db.session.add(ad_mapping)
            db.session.commit()
            flash('Ad mapping updated successfully!', 'success')
            return redirect(url_for('main_bp.manage_ad_mappings'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating ad mapping: {str(e)}', 'danger')

    if request.method == 'GET':
        for mapping in mappings:
            form.keywords.append_entry({'keyword': mapping.keyword})

    return render_template('edit_ad_mapping.html', form=form, mappings=mappings)


@main_bp.route('/delete_ad_mapping/<int:product_id>', methods=['POST'])
@login_required
def delete_ad_mapping(product_id):
    mappings = AdMapping.query.filter_by(user_id=current_user.id, product_id=product_id).all()
    for mapping in mappings:
        db.session.delete(mapping)
    db.session.commit()
    flash('Ad mapping deleted successfully!', 'success')
    return redirect(url_for('main_bp.manage_ad_mappings'))


@main_bp.route('/country_ad_mappings', methods=['GET', 'POST'])
@login_required
def manage_country_ad_mappings():
    form = CountryAdMappingForm()

    # Obtener todos los países del usuario actual que no están mapeados
    mapped_country_ids = [mapping.country_id for mapping in CountryAdMapping.query.filter_by(user_id=current_user.id).all()]
    countries = Country.query.filter(Country.user_id == current_user.id, Country.id.notin_(mapped_country_ids)).order_by(Country.name).all()
    form.country_id.choices = [(country.id, country.name) for country in countries]

    # Obtener todos los valores únicos de países de anuncios de la columna "País (Facebook/TikTok)"
    ad_countries = db.session.query(CampaignData.country_facebook).distinct().all()
    ad_countries = [country[0] for country in ad_countries]
    mapped_ad_countries = [mapping.ad_country for mapping in CountryAdMapping.query.filter_by(user_id=current_user.id).all()]
    ad_countries = [country for country in ad_countries if country not in mapped_ad_countries]
    form.ad_countries.choices = [(country, country) for country in ad_countries]

    if form.validate_on_submit():
        try:
            for ad_country in form.ad_countries.data:
                country_ad_mapping = CountryAdMapping(
                    user_id=current_user.id,
                    country_id=form.country_id.data,
                    ad_country=ad_country,
                )
                db.session.add(country_ad_mapping)
            db.session.commit()
            flash('Country mapped successfully!', 'success')
            return redirect(url_for('main_bp.manage_country_ad_mappings'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error mapping country: {str(e)}', 'danger')

    mappings = CountryAdMapping.query.filter_by(user_id=current_user.id).all()
    grouped_mappings = {}
    for mapping in mappings:
        if mapping.country_id not in grouped_mappings:
            grouped_mappings[mapping.country_id] = {
                'country_id': mapping.country_id,
                'country': mapping.country.name,
                'ad_countries': []
            }
        grouped_mappings[mapping.country_id]['ad_countries'].append(mapping.ad_country)

    return render_template('country_ad_mappings.html', form=form, grouped_mappings=grouped_mappings)

@main_bp.route('/edit_country_ad_mapping/<int:country_id>', methods=['GET', 'POST'])
@login_required
def edit_country_ad_mapping(country_id):
    mappings = CountryAdMapping.query.filter_by(user_id=current_user.id, country_id=country_id).all()
    if not mappings:
        flash('No mappings found for the selected country.', 'danger')
        return redirect(url_for('main_bp.manage_country_ad_mappings'))

    form = CountryAdMappingForm()
    countries = Country.query.filter_by(user_id=current_user.id).all()
    form.country_id.choices = [(country.id, country.name) for country in countries]
    form.country_id.data = country_id

    # Obtener todos los valores únicos de países de anuncios de la columna "País (Facebook/TikTok)"
    ad_countries = db.session.query(CampaignData.country_facebook).distinct().all()
    ad_countries = [country[0] for country in ad_countries]
    form.ad_countries.choices = [(country, country) for country in ad_countries]
    
    if form.validate_on_submit():
        try:
            CountryAdMapping.query.filter_by(user_id=current_user.id, country_id=country_id).delete()
            for ad_country in form.ad_countries.data:
                country_ad_mapping = CountryAdMapping(
                    user_id=current_user.id,
                    country_id=form.country_id.data,
                    ad_country=ad_country,
                )
                db.session.add(country_ad_mapping)
            db.session.commit()
            flash('Country mapping updated successfully!', 'success')
            return redirect(url_for('main_bp.manage_country_ad_mappings'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating country mapping: {str(e)}', 'danger')

    if request.method == 'GET':
        form.ad_countries.data = [mapping.ad_country for mapping in mappings]

    return render_template('edit_country_ad_mappings.html', form=form, mappings=mappings)

@main_bp.route('/delete_country_ad_mapping/<int:country_id>', methods=['POST'])
@login_required
def delete_country_ad_mapping(country_id):
    mappings = CountryAdMapping.query.filter_by(user_id=current_user.id, country_id=country_id).all()
    for mapping in mappings:
        db.session.delete(mapping)
    db.session.commit()
    flash('Country mapping deleted successfully!', 'success')
    return redirect(url_for('main_bp.manage_country_ad_mappings'))


@main_bp.route('/region_ad_mappings', methods=['GET', 'POST'])
@login_required
def manage_region_ad_mappings():
    form = RegionAdMappingForm()
    delete_form = DeleteRegionAdMappingForm()
    
    # Obtener todas las regiones del usuario actual
    regions = Region.query.filter_by(user_id=current_user.id).order_by(Region.name).all()

    # Obtener regiones ya mapeadas
    mapped_region_ids = [mapping.region_id for mapping in RegionAdMapping.query.filter_by(user_id=current_user.id).all()]

    # Filtrar regiones no mapeadas
    unmapped_regions = [region for region in regions if region.id not in mapped_region_ids]

    # Construir opciones para el campo de selección del formulario
    form.region_id.choices = [(region.id, region.name) for region in unmapped_regions]

    # Obtener las regiones de anuncios disponibles para el mapeo, excluyendo las ya mapeadas
    mapped_ad_regions = [mapping.ad_region for mapping in RegionAdMapping.query.filter_by(user_id=current_user.id).all()]
    ad_regions = db.session.query(CampaignData.region_facebook).distinct().all()
    available_ad_regions = [region[0] for region in ad_regions if region[0] not in mapped_ad_regions]
    form.ad_regions.choices = [(region, region) for region in available_ad_regions]

    if form.validate_on_submit():
        try:
            region_id = form.region_id.data
            region_name = dict(form.region_id.choices).get(int(form.region_id.data))

            for ad_region in form.ad_regions.data:
                mapping = RegionAdMapping(
                    user_id=current_user.id,
                    region_id=region_id,
                    ad_region=ad_region
                )
                db.session.add(mapping)
            db.session.commit()
            flash('Region mapped successfully!', 'success')
            return redirect(url_for('main_bp.manage_region_ad_mappings'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error mapping region: {str(e)}', 'danger')

    # Agrupar mapeos por región
    mappings = RegionAdMapping.query.filter_by(user_id=current_user.id).all()
    grouped_mappings = {}
    for mapping in mappings:
        if mapping.region_id not in grouped_mappings:
            grouped_mappings[mapping.region_id] = {
                'region': mapping.region,
                'ad_regions': [],
                'id': mapping.id
            }
        grouped_mappings[mapping.region_id]['ad_regions'].append(mapping.ad_region)

    # Configurar opciones para el formulario de eliminación
    delete_form.region_ids.choices = [(mapping.region_id, mapping.region.name) for mapping in mappings]

    return render_template('region_ad_mappings.html', form=form, delete_form=delete_form, grouped_mappings=grouped_mappings)

@main_bp.route('/edit_region_ad_mappings/<int:region_id>', methods=['GET', 'POST'])
@login_required
def edit_region_ad_mappings(region_id):
    print("Accessing edit_region_ad_mappings with ID:", region_id)
    mapping = RegionAdMapping.query.get_or_404(region_id)
    form = EditRegionAdMappingForm(obj=mapping)  # Assuming you want to edit existing, preload form

    # Configuring choices for region_id with correct format
    form.region_id.choices = [(r.id, r.name) for r in Region.query.filter_by(user_id=current_user.id).all()]

    # Configuring choices for ad_regions, ensure only unique region_facebook entries not currently mapped
    current_mapped_regions = [m.ad_region for m in RegionAdMapping.query.filter_by(user_id=current_user.id).all()]
    available_regions = CampaignData.query.filter(
        CampaignData.user_id == current_user.id, 
        ~CampaignData.region_facebook.in_(current_mapped_regions)
    ).distinct().all()
    form.ad_regions.choices = [(r.region_facebook, r.region_facebook) for r in available_regions]

    if request.method == 'POST':
        if form.validate_on_submit():
            # Mapping updates
            mapping.region_id = form.region_id.data
            # Ensure ad_regions is a string, not a list
            mapping.ad_region = ','.join(form.ad_regions.data) if isinstance(form.ad_regions.data, list) else form.ad_regions.data
            db.session.commit()
            flash('Region ad mapping updated successfully.', 'success')
            return redirect(url_for('main_bp.manage_region_ad_mappings'))

    # On GET or failed validation, preserve the existing selections
    form.region_id.data = mapping.region_id
    form.ad_regions.data = mapping.ad_region.split(',') if isinstance(mapping.ad_region, str) else mapping.ad_region

    return render_template('edit_region_ad_mappings.html', form=form)
@main_bp.route('/delete_region_ad_mappings', methods=['POST'])
@login_required
def delete_region_ad_mappings():
    delete_form = DeleteRegionAdMappingForm()
    delete_form.region_ids.choices = [(m.id, m.region.name) for m in RegionAdMapping.query.filter_by(user_id=current_user.id).all()]

    if delete_form.validate_on_submit():
        region_ids = delete_form.region_ids.data
        for region_id in region_ids:
            mappings = RegionAdMapping.query.filter_by(region_id=region_id, user_id=current_user.id).all()
            for mapping in mappings:
                db.session.delete(mapping)
        
        db.session.commit()
        flash('Mapeos eliminados exitosamente.', 'success')
    
    return redirect(url_for('main_bp.manage_region_ad_mappings'))


@main_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_id = current_user.id
    form = FilterForm()

    # Poblar el campo de selección de países con los países mapeados
    country_mappings = CountryAdMapping.query.filter_by(user_id=user_id).all()
    unique_countries = set([(mapping.country.name, mapping.country.name) for mapping in country_mappings])
    form.country.choices += list(unique_countries)

    # Poblar el campo de selección de regiones con las regiones mapeadas
    region_mappings = RegionAdMapping.query.filter_by(user_id=user_id).all()
    unique_regions = set([(mapping.region.name, mapping.region.name) for mapping in region_mappings])
    form.region.choices += list(unique_regions)

    # Obtener los valores únicos de estado desde SheetData
    linked_sheet = LinkedSheet.query.filter_by(user_id=user_id).first()
    unique_states = set()
    if linked_sheet:
        sheet_data = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
        for data in sheet_data:
            row = json.loads(data.data)
            if len(row) > 14:  # Asegurarse de que la fila tenga al menos 15 columnas
                estado = row[14]  # La columna 15 corresponde al índice 14
                if estado:
                    unique_states.add(estado)

    form.estado.choices += [(state, state) for state in unique_states]

    # Variables para almacenar los filtros seleccionados
    start_date = None
    end_date = None
    selected_country = 'all'
    selected_region = 'all'
    selected_platform = 'all'
    selected_currency = 'USD'
    selected_estado = 'all'

    if form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data
        selected_country = form.country.data
        selected_region = form.region.data
        selected_platform = form.platform.data
        selected_currency = form.currency.data
        selected_estado = form.estado.data

    # Obtener todos los mapeos de anuncios
    ad_mappings = AdMapping.query.filter_by(user_id=user_id).all()
    mapping_dict = {mapping.keyword.lower(): mapping.product.name for mapping in ad_mappings}

    # Obtener los códigos de países asociados al país mapeado seleccionado
    if selected_country != 'all':
        ad_country_codes = [mapping.ad_country for mapping in country_mappings if mapping.country.name == selected_country]
    else:
        ad_country_codes = None

    # Obtener los códigos de regiones asociados a la región mapeada seleccionada
    if selected_region != 'all':
        ad_region_codes = [mapping.ad_region for mapping in region_mappings if mapping.region.name == selected_region]
    else:
        ad_region_codes = None

    # Construir la consulta de campañas
    campaign_query = CampaignData.query.filter_by(user_id=user_id)
    
    if start_date and end_date:
        campaign_query = campaign_query.filter(CampaignData.date >= start_date, CampaignData.date <= end_date)
    
    if ad_country_codes:
        campaign_query = campaign_query.filter(CampaignData.country_facebook.in_(ad_country_codes))
    
    if ad_region_codes:
        campaign_query = campaign_query.filter(CampaignData.region_facebook.in_(ad_region_codes))
    
    if selected_platform != 'all':
        campaign_query = campaign_query.filter(CampaignData.platform == selected_platform)

    campaign_data = campaign_query.all()

    # Crear un diccionario para almacenar los datos agregados por producto
    dashboard_data = {}

    for campaign in campaign_data:
        # Buscar el nombre mapeado del producto
        product_name = 'No mapeado'
        for keyword, product in mapping_dict.items():
            if keyword in campaign.campaign_name.lower():
                product_name = product
                break

        # Convertir el gasto de anuncios a la moneda seleccionada
        ads_spend = campaign.spend
        if selected_currency == 'USD':
            if campaign.currency != 'USD':
                ads_spend = convert_to_usd(campaign.spend, campaign.currency)
        elif selected_currency == 'PEN':
            if campaign.currency == 'USD':
                ads_spend = campaign.spend * 3.7  # Asumimos una tasa de conversión fija
            elif campaign.currency == 'PEN':
                ads_spend = campaign.spend
            else:
                ads_spend = convert_to_pen(campaign.spend, campaign.currency)
        
        # Sumar el gasto de anuncios para el producto correspondiente
        if product_name not in dashboard_data:
            dashboard_data[product_name] = {'ads_spend': 0, 'quantity': 0, 'sales': 0}
        
        dashboard_data[product_name]['ads_spend'] += ads_spend

    # Obtener la hoja vinculada
    if linked_sheet:
        sheet_data_query = SheetData.query.filter_by(sheet_id=linked_sheet.sheet_id).all()
    else:
        sheet_data_query = []

    if start_date and end_date:
        sheet_data = [data for data in sheet_data_query if start_date <= datetime.strptime(json.loads(data.data)[0], '%Y-%m-%d').date() <= end_date]
    else:
        sheet_data = sheet_data_query

    product_mappings = ProductMapping.query.filter_by(user_id=user_id).all()
    product_mapping_dict = {mapping.original_value.lower(): mapping.product.name for mapping in product_mappings}

    # Obtener los mapeos de países y regiones desde SheetData
    sheet_country_mappings = CountryMapping.query.filter_by(user_id=user_id).all()
    sheet_mapped_countries = {mapping.original_value.lower(): mapping.country.name for mapping in sheet_country_mappings}
    sheet_region_mappings = RegionMapping.query.filter_by(user_id=user_id).all()
    sheet_mapped_regions = {mapping.original_value.lower(): mapping.region.name for mapping in sheet_region_mappings}

    for data in sheet_data:
        row = json.loads(data.data)
        date_str = row[0]
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()  # Ajusta el formato según sea necesario
        country_name = sheet_mapped_countries.get(row[8].lower(), 'No mapeado')  # Asumimos que el país está en la columna 8
        region_name = sheet_mapped_regions.get(row[7].lower(), 'No mapeado')  # Asumimos que la región está en la columna 7

        # Filtrar por país
        if selected_country != 'all' and country_name != selected_country:
            continue

        # Filtrar por región
        if selected_region != 'all' and region_name != selected_region:
            continue

        # Filtrar por estado
        estado = row[14] if len(row) > 14 else ''
        if selected_estado != 'all' and estado != selected_estado:
            continue

        if start_date and end_date and start_date <= date_obj <= end_date:
            product_name = product_mapping_dict.get(row[9].lower(), 'No mapeado')  # Asumimos que el nombre del producto está en la columna 9
            quantity = int(row[10]) if row[10] else 0  # Asumimos que la cantidad está en la columna 10
            sales = float(row[11]) if row[11] else 0  # Asumimos que las ventas están en la columna 11

            # Convertir las ventas a la moneda seleccionada
            if selected_currency == 'USD':
                if country_name == 'Peru':
                    sales /= 3.7  # Convertir soles a dólares
                elif country_name == 'Colombia':
                    sales /= 3856.88  # Convertir pesos colombianos a dólares
                elif country_name == 'Ecuador':
                    sales = sales  # Dólares ya están en dólares
                elif country_name == 'Republica Dominicana':
                    sales /= 59.12  # Convertir pesos dominicanos a dólares
                # Añadir más conversiones según sea necesario
            elif selected_currency == 'PEN':
                if country_name == 'Peru':
                    sales = sales  # Ya está en soles
                elif country_name == 'Ecuador':
                    sales *= 3.7  # Convertir dólares a soles
                elif country_name == 'Colombia':
                    sales *= 0.00097  # Convertir pesos colombianos a soles
                elif country_name == 'Republica Dominicana':
                    sales *= 0.063  # Convertir pesos dominicanos a soles
                # Añadir más conversiones según sea necesario

            # Acumular cantidades y ventas en el producto general
            if product_name in dashboard_data:
                dashboard_data[product_name]['quantity'] += quantity
                dashboard_data[product_name]['sales'] += sales
            else:
                dashboard_data[product_name] = {'ads_spend': 0, 'quantity': quantity, 'sales': sales}

    # Filtrar los productos cuyo gasto es mayor a 0, cantidad es mayor a 0, o ventas son mayores a 0
    filtered_dashboard_data = {product: {'ads_spend': format(data['ads_spend'], ',.2f'), 
                                         'quantity': data['quantity'], 
                                         'sales': format(data['sales'], ',.2f')} 
                               for product, data in dashboard_data.items() 
                               if data['ads_spend'] > 0 or data['quantity'] > 0 or data['sales'] > 0}

    return render_template('dashboard.html', form=form, dashboard_data=filtered_dashboard_data)

def convert_to_usd(amount, currency):
    if currency == 'PEN':
        return amount / 3.7
    if currency == 'COP':
        return amount / 3000.7
        
    # Agregar más conversiones según sea necesario
    return amount

def convert_to_pen(amount, currency):
    if currency == 'USD':
        return amount * 3.7
    # Agregar más conversiones según sea necesario
    return amount


@main_bp.route('/warehouses', methods=['GET', 'POST'])
@login_required
def warehouses():
    form = WarehouseForm()
    form.country_id.choices = [(country.id, country.name) for country in Country.query.filter_by(user_id=current_user.id).all()]
    
    if form.validate_on_submit():
        warehouse = Warehouse(name=form.name.data, country_id=form.country_id.data, user_id=current_user.id)
        db.session.add(warehouse)
        db.session.commit()
        flash('Warehouse created successfully!')
        return redirect(url_for('main_bp.warehouses'))
    
    warehouses = Warehouse.query.filter_by(user_id=current_user.id).all()
    return render_template('warehouses.html', form=form, warehouses=warehouses)

@main_bp.route('/warehouses/edit/<int:warehouse_id>', methods=['GET', 'POST'])
@login_required
def edit_warehouse(warehouse_id):
    warehouse = Warehouse.query.get_or_404(warehouse_id)
    if warehouse.user_id != current_user.id:
        flash('You do not have permission to edit this warehouse.')
        return redirect(url_for('main_bp.warehouses'))

    form = WarehouseForm(obj=warehouse)
    form.country_id.choices = [(country.id, country.name) for country in Country.query.filter_by(user_id=current_user.id).all()]

    product_form = WarehouseProductForm()
    product_form.product_id.choices = [(product.id, product.name) for product in Product.query.filter_by(user_id=current_user.id).all()]

    # Poblar las variantes en función del producto seleccionado
    if request.method == 'GET':
        selected_product_id = request.args.get('product_id', type=int)
        if selected_product_id:
            product_form.product_id.data = selected_product_id
            product_form.variant_id.choices = [(0, 'No Variant')] + [(v.id, v.name) for v in Variant.query.filter_by(product_id=selected_product_id).all()]
        else:
            product_form.variant_id.choices = [(0, 'No Variant')]
    
    if request.method == 'POST':
        product_form.variant_id.choices = [(0, 'No Variant')] + [(v.id, v.name) for v in Variant.query.filter_by(product_id=product_form.product_id.data).all()]
        
        logger.debug(f"Form data: {product_form.data}")

        if product_form.validate_on_submit():
            product_id = product_form.product_id.data
            variant_id = product_form.variant_id.data if product_form.variant_id.data != 0 else None
            quantity = product_form.quantity.data
            cost = product_form.cost.data

            logger.debug(f"Adding product to warehouse: product_id={product_id}, variant_id={variant_id}, quantity={quantity}, cost={cost}")

            try:
                warehouse_product = WarehouseProduct(
                    warehouse_id=warehouse.id,
                    product_id=product_id,
                    variant_id=variant_id,
                    quantity=quantity,
                    cost=cost
                )
                db.session.add(warehouse_product)
                db.session.commit()
                flash('Product added to warehouse successfully!')
                logger.debug("Product added successfully")
            except Exception as e:
                db.session.rollback()
                flash(f"Error adding product: {str(e)}")
                logger.error(f"Error adding product: {str(e)}")
            return redirect(url_for('main_bp.edit_warehouse', warehouse_id=warehouse.id))
        else:
            logger.debug("Form validation failed")
            logger.debug(product_form.errors)

    warehouse_products = WarehouseProduct.query.filter_by(warehouse_id=warehouse.id).all()
    return render_template('edit_warehouse.html', form=form, product_form=product_form, warehouse=warehouse, warehouse_products=warehouse_products)

@main_bp.route('/get_variants/<int:product_id>')
@login_required
def get_variants(product_id):
    variants = Variant.query.filter_by(product_id=product_id).all()
    return jsonify({'variants': [{'id': v.id, 'name': v.name} for v in variants]})


@main_bp.route('/warehouses/<int:warehouse_id>/edit_product/<int:warehouse_product_id>', methods=['GET', 'POST'])
@login_required
def edit_warehouse_product(warehouse_id, warehouse_product_id):
    warehouse_product = WarehouseProduct.query.get_or_404(warehouse_product_id)
    if warehouse_product.warehouse.user_id != current_user.id:
        flash('You do not have permission to edit this product in the warehouse.')
        return redirect(url_for('main_bp.warehouse_products', warehouse_id=warehouse_id))

    form = WarehouseProductForm(obj=warehouse_product)
    form.product_id.choices = [(product.id, product.name) for product in Product.query.filter_by(user_id=current_user.id).all()]
    form.variant_id.choices = [(v.id, v.name) for v in Variant.query.filter_by(product_id=warehouse_product.product_id).all()]

    if form.validate_on_submit():
        warehouse_product.product_id = form.product_id.data
        warehouse_product.variant_id = form.variant_id.data if form.variant_id.data else None
        warehouse_product.quantity = form.quantity.data
        warehouse_product.cost = form.cost.data
        db.session.commit()
        flash('Product in warehouse updated successfully!')
        return redirect(url_for('main_bp.warehouse_products', warehouse_id=warehouse_id))
    
    return render_template('edit_warehouse_product.html', form=form, warehouse_id=warehouse_id)

@main_bp.route('/warehouses/delete/<int:warehouse_id>', methods=['POST'])
@login_required
def delete_warehouse(warehouse_id):
    warehouse = Warehouse.query.get_or_404(warehouse_id)
    if warehouse.user_id != current_user.id:
        flash('You do not have permission to delete this warehouse.')
        return redirect(url_for('main_bp.warehouses'))
    
    db.session.delete(warehouse)
    db.session.commit()
    flash('Warehouse deleted successfully!')
    return redirect(url_for('main_bp.warehouses'))

@main_bp.route('/warehouses/<int:warehouse_id>/delete_product/<int:warehouse_product_id>', methods=['POST'])
@login_required
def delete_warehouse_product(warehouse_id, warehouse_product_id):
    warehouse_product = WarehouseProduct.query.get_or_404(warehouse_product_id)
    if warehouse_product.warehouse.user_id != current_user.id:
        flash('You do not have permission to delete this product from the warehouse.')
        return redirect(url_for('main_bp.warehouse_products', warehouse_id=warehouse_id))
    
    db.session.delete(warehouse_product)
    db.session.commit()
    flash('Product removed from warehouse successfully!')
    return redirect(url_for('main_bp.warehouse_products', warehouse_id=warehouse_id))


@main_bp.route('/warehouses/<int:warehouse_id>/products', methods=['GET', 'POST'])
@login_required
def warehouse_products(warehouse_id):
    warehouse = Warehouse.query.get_or_404(warehouse_id)
    if warehouse.user_id != current_user.id:
        flash('You do not have permission to view this warehouse.')
        return redirect(url_for('main_bp.warehouses'))
    
    form = WarehouseProductForm()
    form.product_id.choices = [(product.id, product.name) for product in Product.query.filter_by(user_id=current_user.id).all()]
    form.variant_id.choices = [(variant.id, variant.name) for variant in Variant.query.all()]
    
    if form.validate_on_submit():
        warehouse_product = WarehouseProduct(
            warehouse_id=warehouse.id,
            product_id=form.product_id.data,
            variant_id=form.variant_id.data if form.variant_id.data else None,
            quantity=form.quantity.data,
            cost=form.cost.data
        )
        db.session.add(warehouse_product)
        db.session.commit()
        flash('Product added to warehouse successfully!')
        return redirect(url_for('main_bp.warehouse_products', warehouse_id=warehouse.id))
    
    warehouse_products = WarehouseProduct.query.filter_by(warehouse_id=warehouse.id).all()
    return render_template('warehouse_products.html', form=form, warehouse=warehouse, warehouse_products=warehouse_products)


@main_bp.route('/warehouses/<int:warehouse_id>/add_product', methods=['POST'])
@login_required
def add_warehouse_product(warehouse_id):
    form = WarehouseProductForm()
    form.product_id.choices = [(product.id, product.name) for product in Product.query.filter_by(user_id=current_user.id).all()]
    form.variant_id.choices = [(0, 'No Variant')] + [(v.id, v.name) for v in Variant.query.filter_by(product_id=form.product_id.data).all()]

    if form.validate_on_submit():
        try:
            product_id = form.product_id.data
            variant_id = form.variant_id.data if form.variant_id.data != 0 else None
            quantity = form.quantity.data
            cost = form.cost.data

            warehouse_product = WarehouseProduct(
                warehouse_id=warehouse_id,
                product_id=product_id,
                variant_id=variant_id,
                quantity=quantity,
                cost=cost
            )
            db.session.add(warehouse_product)
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})

    errors = form.errors
    return jsonify({'success': False, 'error': 'Invalid form data', 'errors': errors})


@main_bp.route('/warehouses/<int:warehouse_id>/products_list', methods=['GET'])
@login_required
def get_warehouse_products(warehouse_id):
    warehouse_products = WarehouseProduct.query.filter_by(warehouse_id=warehouse_id).all()
    products = []
    for wp in warehouse_products:
        products.append({
            'id': wp.id,
            'name': wp.product.name,
            'variant': wp.variant.name if wp.variant else 'No Variant',
            'quantity': wp.quantity,
            'cost': wp.cost,
            'warehouse_id': warehouse_id
        })
    return jsonify({'products': products})
