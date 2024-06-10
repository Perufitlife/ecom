from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import jwt
from time import time
from .config import Config
from . import login
from datetime import datetime, timezone

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    products = db.relationship('Product', backref='user', lazy=True)
    countries = db.relationship('Country', backref='user', lazy=True)
    regions = db.relationship('Region', backref='user', lazy=True)
    linked_sheets = db.relationship('LinkedSheet', backref='owner', lazy='dynamic')
    country_mappings = db.relationship('CountryMapping', back_populates='user')
    region_mappings = db.relationship('RegionMapping', back_populates='user')
    accounts = db.relationship('Account', back_populates='user', lazy=True)
    ad_mappings = db.relationship('AdMapping', back_populates='user', lazy=True)
    country_ad_mappings = db.relationship('CountryAdMapping', back_populates='user', lazy=True)


    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            Config.SECRET_KEY, algorithm='HS256'
        )

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    variants = db.relationship('Variant', backref='product', lazy='dynamic')

    def __repr__(self):
        return f'<Product {self.name}>'


class Variant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))

    def __repr__(self):
        return f'<Variant {self.name}>'

class Country(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mappings = db.relationship('CountryMapping', back_populates='country')
    ad_mappings = db.relationship('CountryAdMapping', back_populates='country')

    def __repr__(self):
        return '<Country {}>'.format(self.name)

class Region(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    country_id = db.Column(db.Integer, db.ForeignKey('country.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    region_mappings = db.relationship('RegionMapping', back_populates='region')

    def __repr__(self):
        return '<Region {}>'.format(self.name)

class GoogleSheet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sheet_id = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(256), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    tab_name = db.Column(db.String(256))

class SheetData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sheet_id = db.Column(db.String(128), nullable=False)
    unique_key = db.Column(db.String(500), nullable=False)
    data = db.Column(db.Text, nullable=False)
    mapped_data = db.Column(db.Text, nullable=True)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)  # Define la columna con un valor por defecto
    estado = db.Column(db.String(100))  # Nueva columna para estado
    linked_sheet_id = db.Column(db.Integer, db.ForeignKey('linked_sheet.id'), nullable=True)  # Permitir valores nulos


class LinkedSheet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sheet_id = db.Column(db.String(256), nullable=False)
    sheet_name = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class ProductMapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sheet_id = db.Column(db.Integer, nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    variant_id = db.Column(db.Integer, db.ForeignKey('variant.id'), nullable=True)
    original_value = db.Column(db.String(64), nullable=False)
    mapped_value = db.Column(db.String(64), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
    product = db.relationship('Product', backref='mappings', lazy=True)
    variant = db.relationship('Variant', backref='mappings', lazy=True)
    user = db.relationship('User', backref='product_mappings', lazy=True)


class SheetHeaders(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sheet_id = db.Column(db.String(128), nullable=False)
    headers = db.Column(db.Text, nullable=False)

class CountryMapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sheet_id = db.Column(db.String(128), nullable=False)
    country_id = db.Column(db.Integer, db.ForeignKey('country.id'), nullable=False)
    original_value = db.Column(db.String(256), nullable=False)
    mapped_value = db.Column(db.String(256), nullable=False)
    date_added = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', back_populates='country_mappings')
    country = db.relationship('Country', back_populates='mappings')

    def __repr__(self):
        return '<CountryMapping {}>'.format(self.id)

class RegionMapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sheet_id = db.Column(db.String(64), nullable=False)
    region_id = db.Column(db.Integer, db.ForeignKey('region.id'), nullable=False)
    original_value = db.Column(db.String(64), nullable=False)
    mapped_value = db.Column(db.String(64), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='region_mappings')
    region = db.relationship('Region', back_populates='region_mappings')

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(80))
    account_type = db.Column(db.String(80))
    token = db.Column(db.String(200))
    ad_accounts = db.Column(db.String(750), default='')
    linked_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='accounts')

class CampaignData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_name = db.Column(db.String(250), nullable=False)
    product_name = db.Column(db.String(250), default='Pending')
    country_facebook = db.Column(db.String(100))
    country_real = db.Column(db.String(100), default='Pending')
    region_facebook = db.Column(db.String(100))
    region_real = db.Column(db.String(100), default='Pending')
    spend = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), nullable=False, default='USD')
    date = db.Column(db.Date, nullable=False)
    account_id = db.Column(db.String(500), nullable=False)
    platform = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    region = db.Column(db.String(255))
    country = db.Column(db.String(255))

    __table_args__ = (
        db.UniqueConstraint('campaign_name', 'region_facebook', 'date'),
    )

class AdMapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    keyword = db.Column(db.String(256), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='ad_mappings')
    product = db.relationship('Product', back_populates='ad_mappings')

User.ad_mappings = db.relationship('AdMapping', back_populates='user', lazy=True)
Product.ad_mappings = db.relationship('AdMapping', back_populates='product', lazy=True)

class CountryAdMapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    country_id = db.Column(db.Integer, db.ForeignKey('country.id'), nullable=False)
    ad_country = db.Column(db.String(256), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='country_ad_mappings')
    country = db.relationship('Country', back_populates='ad_mappings')

    def __repr__(self):
        return '<CountryAdMapping {}>'.format(self.id)

class RegionAdMapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    region_id = db.Column(db.Integer, db.ForeignKey('region.id'), nullable=False)
    ad_region = db.Column(db.String(256), nullable=False)
    date_added = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', back_populates='region_ad_mappings')
    region = db.relationship('Region', back_populates='region_ad_mappings')

    def __repr__(self):
        return '<RegionAdMapping {}>'.format(self.id)

User.region_ad_mappings = db.relationship('RegionAdMapping', back_populates='user', lazy=True)
Region.region_ad_mappings = db.relationship('RegionAdMapping', back_populates='region', lazy=True)

class Warehouse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    country_id = db.Column(db.Integer, db.ForeignKey('country.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    country = db.relationship('Country', backref=db.backref('warehouses', lazy=True))
    user = db.relationship('User', backref=db.backref('warehouses', lazy=True))

class WarehouseProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouse.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    variant_id = db.Column(db.Integer, db.ForeignKey('variant.id'), nullable=True)
    quantity = db.Column(db.Integer, nullable=False)
    cost = db.Column(db.Float, nullable=False)

    warehouse = db.relationship('Warehouse', backref=db.backref('warehouse_products', lazy=True))
    product = db.relationship('Product', backref=db.backref('product_warehouses', lazy=True))
    variant = db.relationship('Variant', backref=db.backref('variant_warehouses', lazy=True))

