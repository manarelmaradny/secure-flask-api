import datetime, io, qrcode, pyotp, jwt
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from PIL import Image

# Flask app config
app = Flask(__name__)
app.config['SECRET_KEY'] = '1d4d9db6289b449bd01ffd8d1bb7c6dd79932dcfc3053cd996307ad7b8c9d218'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/secure_api'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    twofa_secret = db.Column(db.String(256), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    price = db.Column(db.Numeric(10, 2))
    quantity = db.Column(db.Integer)

# JWT Token Decorator
def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(payload['user_id'])
        except:
            return jsonify({'message': 'Token is invalid or expired'}), 401
        return f(current_user, *args, **kwargs)
    return wrapper

# Register Endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'User already exists'}), 400

    hashed = generate_password_hash(data['password'])
    secret = pyotp.random_base32()
    user = User(username=data['username'], password=hashed, twofa_secret=secret)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', '2FA_secret': secret}), 201

# QR Code Endpoint for Google Authenticator
@app.route('/qrcode/<username>', methods=['GET'])
def qr(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    uri = pyotp.TOTP(user.twofa_secret).provisioning_uri(name=user.username, issuer_name="SecureAPI")
    qr_img = qrcode.make(uri)
    img_io = io.BytesIO()
    qr_img.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png')

# Login + 2FA + JWT Token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username, password, code = data.get('username'), data.get('password'), data.get('twofa_code')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    if not pyotp.TOTP(user.twofa_secret).verify(code):
        return jsonify({'error': 'Invalid 2FA code'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token})

# CRUD: Create Product
@app.route('/products', methods=['POST'])
@token_required
def create_product(current_user):
    data = request.get_json()
    product = Product(
        name=data['name'],
        description=data.get('description'),
        price=data.get('price', 0),
        quantity=data.get('quantity', 0)
    )
    db.session.add(product)
    db.session.commit()
    return jsonify({'message': 'Product added', 'id': product.id})

# CRUD: Read All Products
@app.route('/products', methods=['GET'])
@token_required
def get_all_products(current_user):
    products = Product.query.all()
    result = [{
        'id': p.id,
        'name': p.name,
        'description': p.description,
        'price': str(p.price),
        'quantity': p.quantity
    } for p in products]
    return jsonify(result)

# CRUD: Read One Product
@app.route('/products/<int:id>', methods=['GET'])
@token_required
def get_product(current_user, id):
    p = Product.query.get(id)
    if not p:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({
        'id': p.id, 'name': p.name, 'description': p.description,
        'price': str(p.price), 'quantity': p.quantity
    })

# CRUD: Update Product
@app.route('/products/<int:id>', methods=['PUT'])
@token_required
def update_product(current_user, id):
    p = Product.query.get(id)
    if not p:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json()
    p.name = data.get('name', p.name)
    p.description = data.get('description', p.description)
    p.price = data.get('price', p.price)
    p.quantity = data.get('quantity', p.quantity)
    db.session.commit()
    return jsonify({'message': 'Product updated'})

# CRUD: Delete Product
@app.route('/products/<int:id>', methods=['DELETE'])
@token_required
def delete_product(current_user, id):
    p = Product.query.get(id)
    if not p:
        return jsonify({'error': 'Not found'}), 404
    db.session.delete(p)
    db.session.commit()
    return jsonify({'message': 'Product deleted'})

# Run App with Context
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
