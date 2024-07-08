import os
from flask import Flask, request, jsonify, session
from flask_pymongo import PyMongo
from flask_bcrypt import bcrypt
from flask_cors import CORS  # Import CORS from flask_cors
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)

app = Flask(__name__)
# Set configurations from environment variables
app.secret_key = os.environ.get('SECRET_KEY', '8b88cc50b49b3d0526a00170608644681fa82132a1eed3b9')  # Replace with a default or production key
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'pX~-ERh5AzgZ#Be3?W9^vnKu}Vs_D')  # Set JWT secret key from environment variable
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

# Configure MongoDB
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/Master')  # Set MongoDB URI from environment variable
mongo = PyMongo(app)
# bcrypt = bcrypt(app)
jwt = JWTManager(app)

# Enable CORS for your app with specific origins
CORS(app)
jwt_blacklist = set()

@app.route('/signup', methods=['POST'])
def signup():
    print("Signup route accessed")
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store the user in MongoDB (you should have a 'users' collection)
    users = mongo.db.User1
    existing_user = users.find_one({'username': username})

    if existing_user:
        return jsonify({'message': 'User already exists'})
    
    try:
        # Insert the user with username, email, and hashed_password
        users.insert_one({'username': username, 'email': email, 'password': hashed_password})
        return jsonify({'message': 'Signup successful'})
    except Exception as e:
        print('Error during signup:', str(e))
        return jsonify({'message': 'Error during signup'})
    
    

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Fetch the user from MongoDB (you should have a 'users' collection)
    users = mongo.db.User1
    user = users.find_one({'username': username})

    if not user:
        return jsonify({'message': 'User not found'}), 401

    hashed_password = user['password']

    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        access_token =  create_access_token(identity=username)
        return jsonify({'message': 'Login successful', 'access_token': access_token}),200
    else:
        return jsonify({'message': 'Login failed', 'error': 'Invalid credentials'}), 401


@app.route('/logout', methods=['GET'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    jwt_blacklist.add(jti)

    # print(f'Token added to blacklist: {jti}')
    return jsonify({'message': 'Logout successful'})


from flask_jwt_extended import jwt_required, get_jwt_identity

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    jti = get_jwt()['jti']

    # Check if the token is in the blacklist
    if jti in jwt_blacklist:
        return jsonify({'message': 'Token has been revoked'}), 401
    
    return jsonify(logged_in_as=current_user), 200



# @app.route('/signout', methods=['GET'])
# def signout():
    
#     session.clear()
#     return jsonify({'message': 'Signout successful'})



if __name__ == '__main__':
    app.run(debug=True)
