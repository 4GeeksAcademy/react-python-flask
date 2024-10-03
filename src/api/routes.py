"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import  JWTManager, create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)
jwt = JWTManager()
@api.route('/signup', methods=['POST'])
def add_user():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            print(f"Error: Datos incompletos - Email: {email}, Password: {'Proporcionado' if password else 'No proporcionado'}")
            return jsonify({"error": "Se requieren email y contraseña"}), 400
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"error": "email ya registrado"}), 400
        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email,
            password=hashed_password
            )
        db.session.add(new_user)
        print(f"Creando nuevo usuario con email: {email}")
        db.session.commit()
        print(f"Usuario creado exitosamente: {email}")
        return jsonify({"OK": "Usuario creado exitosamente"}), 201 
    except Exception as e:
        print(f"Error en el servidor: {e}")
        return jsonify({'error': "falla en el servidor"}), 500
@api.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            print(f"Error: Datos incompletos - Email: {email}, Password: {'Proporcionado' if password else 'No proporcionado'}")
            return jsonify({"error": "Se requieren email y contraseña"}), 400
        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            return jsonify({"error": "email no existe"}), 400
        password_db= existing_user.password
        if check_password_hash(password_db, password):
            access_token = create_access_token(identity=existing_user.id)
            return jsonify({
            'access_token': access_token, 
            'id': existing_user.id,
            'email': existing_user.email,
            }), 200
        else:
            return jsonify({"error": "Correo y contraseña no coinciden"}), 401
    except Exception as e:
        print(f"Error en el servidor: {e}")
        return jsonify({'error': "falla en el servidor"}), 500