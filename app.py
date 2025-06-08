from flask import Flask, jsonify, request, g, make_response
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    get_jwt_identity, jwt_required, verify_jwt_in_request, get_jwt
)
from supabase import create_client, Client as SupabaseClient
import os
from dotenv import load_dotenv
from datetime import timedelta, datetime
import logging
from functools import wraps

# Load environment variables
load_dotenv()

# Supabase credentials
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')  # Make sure this matches your .env file

print("\n=== Initializing Supabase Client ===")
print(f"SUPABASE_URL: {'✓' if supabase_url else '✗'}")
print(f"SUPABASE_KEY: {'✓' if supabase_key else '✗'}")

# Initialize the Supabase client globally
supabase = None

def get_supabase() -> SupabaseClient:
    """Get or initialize the Supabase client"""
    global supabase
    
    if supabase is None:
        if not supabase_url or not supabase_key:
            raise RuntimeError("Supabase URL or Key not found in environment variables")
            
        try:
            print("Initializing new Supabase client...")
            # Create client with explicit options to avoid version compatibility issues
            supabase = create_client(
                supabase_url, 
                supabase_key,
                options={
                    'auto_refresh_token': True,
                    'persist_session': True
                }
            )
            print("✓ Supabase client initialized successfully")
        except Exception as e:
            print(f"✗ Failed to initialize Supabase: {e}")
            print(f"Error type: {type(e).__name__}")
            
            # Try alternative initialization without options
            try:
                print("Trying alternative initialization...")
                supabase = create_client(supabase_url, supabase_key)
                print("✓ Supabase client initialized with basic setup")
            except Exception as e2:
                print(f"✗ Alternative initialization also failed: {e2}")
                raise RuntimeError(f"Failed to initialize Supabase client: {e}")
    
    return supabase

# Admin role check decorator
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt()
        if not claims.get('is_admin', False):
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

def create_app():
    app = Flask(__name__)

    # Config
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-in-prod')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'change-this-too')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

    # CORS with more specific configuration
    CORS(
        app,
        resources={
            r"/*": {
                "origins": ["http://localhost:5173", "http://localhost:5174"],
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "supports_credentials": True,
                "expose_headers": ["Content-Range", "X-Total-Count"]
            }
        },
        supports_credentials=True
    )
    
    # Handle preflight requests
    @app.before_request
    def handle_preflight():
        if request.method == "OPTIONS":
            response = make_response()
            response.headers.add("Access-Control-Allow-Origin", request.headers.get("Origin", "*"))
            response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
            response.headers.add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
            response.headers.add("Access-Control-Allow-Credentials", "true")
            return response, 200
        return None

    # JWT
    jwt = JWTManager(app)

    # Initialize Supabase client when app is created
    try:
        get_supabase()
        print("✓ Supabase client ready")
    except Exception as e:
        print(f"✗ Supabase initialization failed: {e}")

    # JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({"error": "Token has expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({"error": "Invalid token"}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({"error": "Authorization token is required"}), 401

    # Register
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        try:
            print("\n=== New Registration Request ===")
            print(f"Request headers: {request.headers}")
            print(f"Request data: {request.get_data()}")
            
            data = request.get_json()
            if not data:
                print("Error: No JSON data received")
                return jsonify({"error": "No data provided"}), 400
                
            print(f"Parsed JSON data: {data}")
            
            # Required fields
            for f in ['email', 'password', 'name']:
                if not data.get(f):
                    error_msg = f"{f} is required"
                    print(f"Validation error: {error_msg}")
                    return jsonify({"error": error_msg}), 400

            if '@' not in data['email']:
                error_msg = "Invalid email format"
                print(f"Validation error: {error_msg}")
                return jsonify({"error": error_msg}), 400
                
            if len(data['password']) < 6:
                error_msg = "Password too short"
                print(f"Validation error: {error_msg}")
                return jsonify({"error": error_msg}), 400

            print("Attempting to sign up with Supabase...")
            try:
                res = get_supabase().auth.sign_up({
                    'email': data['email'],
                    'password': data['password'],
                    'options': {
                        'data': {
                            'name': data['name'], 
                            'company': data.get('company','')
                        }
                    }
                })
                print(f"Supabase response: {res}")
            except Exception as e:
                print(f"Supabase error: {str(e)}")
                return jsonify({"error": f"Authentication service error: {str(e)}"}), 500

            if not getattr(res, 'user', None):
                error_msg = "Registration failed; user might already exist or there was an error."
                print(error_msg)
                return jsonify({"error": error_msg}), 400

            user = res.user
            
            # After successful signup, insert user data into the users table
            try:
                supabase = get_supabase()
                supabase.table('users').insert({
                    'id': user.id,
                    'email': data['email'],
                    'name': data['name'],
                    'company': data.get('company', '')
                }).execute()
                print("✓ User data saved to database")
            except Exception as e:
                print(f"Error saving user data to database: {str(e)}")
                # Delete the auth user if database insertion fails
                try:
                    supabase.auth.admin.delete_user(user.id)
                except Exception as delete_error:
                    print(f"Error cleaning up auth user: {str(delete_error)}")
                return jsonify({"error": "Failed to create user profile"}), 500
                
            access = create_access_token(identity=user.id)
            refresh = create_refresh_token(identity=user.id)

            return jsonify({
                "message": "User registered",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": data['name'],
                    "company": data.get('company', ''),
                    "email_confirmed": user.email_confirmed_at is not None
                },
                "access_token": access,
                "refresh_token": refresh
            }), 201

        except Exception as e:
            msg = str(e).lower()
            if "already registered" in msg:
                return jsonify({"error": "User already exists"}), 409
            return jsonify({"error": "Registration error"}), 400

    # Login
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        try:
            data = request.get_json() or {}
            if not data.get('email') or not data.get('password'):
                return jsonify({"error": "Email and password required"}), 400

            print(f"Attempting to login with email: {data['email']}")
            
            try:
                supabase = get_supabase()
                res = supabase.auth.sign_in_with_password({
                    'email': data['email'],
                    'password': data['password']
                })
                print(f"Supabase login response: {res}")
                
                if not res or not hasattr(res, 'user') or not res.user:
                    print("No user found in response")
                    return jsonify({"error": "Invalid email or password"}), 401

                user = res.user
                
                # Get the latest user data from the database
                db_user = supabase.table('users').select('*').eq('id', user.id).execute()
                if db_user.data:
                    user_data = db_user.data[0]
                else:
                    # Fallback to user_metadata if user not found in custom table
                    user_data = user.user_metadata or {}
                
                print(f"Login successful for user: {user.id}")
                
                access = create_access_token(identity=user.id)
                refresh = create_refresh_token(identity=user.id)

                return jsonify({
                    "message": "Login successful",
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "name": user_data.get('name', ''),
                        "company": user_data.get('company', ''),
                        "email_confirmed": user.email_confirmed_at is not None
                    },
                    "access_token": access,
                    "refresh_token": refresh
                })

            except Exception as e:
                print(f"Login error: {str(e)}")
                if hasattr(e, 'message') and 'Invalid login credentials' in str(e):
                    return jsonify({"error": "Invalid email or password"}), 401
                return jsonify({"error": "Login failed. Please try again."}), 500

        except Exception as e:
            print(f"Unexpected error in login: {str(e)}")
            return jsonify({"error": "An error occurred during login"}), 500

    # Refresh
    @app.route('/api/auth/refresh', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh():
        new_token = create_access_token(identity=get_jwt_identity())
        return jsonify({"access_token": new_token})

    # Logout
    @app.route('/api/auth/logout', methods=['POST'])
    @jwt_required()
    def logout():
        try:
            get_supabase().auth.sign_out()
        except Exception:
            pass
        return jsonify({"message": "Logged out"})

    # Current user
    @app.route('/api/auth/me', methods=['GET'])
    @jwt_required()
    def me():
        res = get_supabase().auth.get_user()
        user = res.user
        return jsonify({
            "id": user.id, "email": user.email,
            "name": user.user_metadata.get('name',''),
            "company": user.user_metadata.get('company',''),
            "email_confirmed": user.email_confirmed_at is not None,
            "created_at": user.created_at
        })

    # Health check
    @app.route('/api/health', methods=['GET'])
    def health():
        supabase_connected = False
        try:
            get_supabase()
            supabase_connected = True
        except Exception:
            pass
        return jsonify({"status":"ok","supabase_connected": supabase_connected})

    # Test Supabase
    @app.route('/api/test-supabase', methods=['GET'])
    def test_supabase():
        try:
            get_supabase().auth.get_user()
            return jsonify({"status":"success","client_initialized":True})
        except Exception as e:
            return jsonify({"status":"error","message":str(e)}), 500

        # Admin authentication routes
    @app.route('/api/admin/login', methods=['POST', 'OPTIONS'])
    def admin_login():
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        try:
            data = request.get_json()
            if not data or 'email' not in data or 'password' not in data:
                return jsonify({"error": "Email and password are required"}), 400
                
            # In a real app, verify credentials against your database
            # This is a simplified example with hardcoded credentials
            if data['email'] == 'admin@example.com' and data['password'] == 'admin123':
                access_token = create_access_token(
                    identity=1,
                    additional_claims={
                        "is_admin": True,
                        "email": "admin@example.com"
                    }
                )
                refresh_token = create_refresh_token(
                    identity=1,
                    additional_claims={
                        "is_admin": True,
                        "email": "admin@example.com"
                    }
                )
                response_data = {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": 1,
                        "email": "admin@example.com",
                        "name": "Admin",
                        "role": "admin"
                    },
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }
                response = jsonify(response_data)
                response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
                response.headers.add('Access-Control-Allow-Credentials', 'true')
                response.headers.add('Access-Control-Expose-Headers', 'Content-Type,Authorization')
                return response
            
            return jsonify({"error": "Invalid credentials"}), 401
            
        except Exception as e:
            print(f"Admin login error: {str(e)}")
            return jsonify({"error": "Login failed"}), 500

    @app.route('/api/admin/profile', methods=['GET', 'OPTIONS'])
    @jwt_required()
    @admin_required
    def admin_profile():
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        current_user = get_jwt_identity()
        claims = get_jwt()
        
        # In a real app, fetch admin user details from database
        response = jsonify({
            "id": current_user,
            "email": claims.get('email'),
            "name": "Admin User",
            "role": "admin"
        })
        response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    @app.route('/api/admin/users', methods=['GET', 'OPTIONS'])
    @jwt_required()
    @admin_required
    def admin_users():
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        try:
            # In a real app, fetch users from database with pagination
            response_data = {
                "users": [
                    {"id": 1, "email": "user1@example.com", "name": "User One", "role": "user"},
                    {"id": 2, "email": "user2@example.com", "name": "User Two", "role": "user"}
                ],
                "total": 2,
                "page": 1,
                "per_page": 10
            }
            response = jsonify(response_data)
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
        except Exception as e:
            response = jsonify({"error": str(e)})
            response.status_code = 500
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

    # Product Management Endpoints
    @app.route('/api/admin/products', methods=['GET', 'OPTIONS'])
    @jwt_required()
    @admin_required
    def admin_products_list():
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        try:
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 10))
            search = request.args.get('search', '')
            
            # In a real app, you would query your database here
            # This is a mock implementation
            products = []
            total = 0
            
            response_data = {
                'products': products,
                'total': total,
                'page': page,
                'per_page': per_page
            }
            
            response = jsonify(response_data)
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        except Exception as e:
            print(f"Error fetching products: {str(e)}")
            response = jsonify({"error": "Failed to fetch products"})
            response.status_code = 500
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

    @app.route('/api/admin/products', methods=['POST', 'OPTIONS'])
    @jwt_required()
    @admin_required
    def admin_create_product():
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        try:
            data = request.get_json()
            
            # Basic validation
            required_fields = ['name', 'price', 'stock', 'sku']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({"error": f"{field} is required"}), 400
            
            # In a real app, you would save to your database here
            # This is a mock implementation
            new_product = {
                'id': 'mock-id-123',
                'name': data['name'],
                'description': data.get('description', ''),
                'price': float(data['price']),
                'brand': data.get('brand'),
                'power_type': data.get('powerType'),
                'stock': int(data['stock']),
                'sku': data['sku'],
                'images': data.get('images', []),
                'specifications': data.get('specifications', []),
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
            
            response = jsonify(new_product)
            response.status_code = 201
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response
            
        except Exception as e:
            print(f"Error creating product: {str(e)}")
            response = jsonify({"error": "Failed to create product"})
            response.status_code = 500
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

    @app.route('/api/admin/refresh-token', methods=['POST', 'OPTIONS'])
    @jwt_required(refresh=True)
    def admin_refresh_token():
        if request.method == 'OPTIONS':
            response = make_response()
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
            response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            response.headers.add('Access-Control-Expose-Headers', 'Content-Type,Authorization')
            return response
            
        try:
            refresh_token = request.json.get('refresh_token')
            if not refresh_token:
                return jsonify({"error": "Refresh token is required"}), 400
                
            current_user = get_jwt_identity()
            claims = get_jwt()
            
            if not claims.get('is_admin', False):
                return jsonify({"error": "Admin access required"}), 403
                
            # Create new access token
            access_token = create_access_token(
                identity=current_user,
                additional_claims={
                    "is_admin": True,
                    "email": claims.get('email', 'admin@example.com')
                }
            )
            
            response = jsonify({
                "access_token": access_token,
                "refresh_token": refresh_token  # Return the same refresh token
            })
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            response.headers.add('Access-Control-Expose-Headers', 'Content-Type,Authorization')
            return response
            
        except Exception as e:
            print(f"Error refreshing token: {str(e)}")
            response = jsonify({"error": "Failed to refresh token"})
            response.status_code = 401
            response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
            response.headers.add('Access-Control-Allow-Credentials', 'true')
            return response

    # Sample product routes
    @app.route('/api/products', methods=['GET'])
    def get_products():
        return jsonify({"products":[
            {"id":1,"name":"Cordless Drill","price":129.99,"inStock":True},
            {"id":2,"name":"Circular Saw","price":149.99,"inStock":True},
            {"id":3,"name":"Hammer Drill","price":179.99,"inStock":False}
        ]})

    @app.route('/api/products/<int:product_id>', methods=['GET'])
    def get_product(product_id):
        products = [
            {"id":1,"name":"Cordless Drill","price":129.99,"inStock":True},
            {"id":2,"name":"Circular Saw","price":149.99,"inStock":True},
            {"id":3,"name":"Hammer Drill","price":179.99,"inStock":False}
        ]
        product = next((p for p in products if p['id']==product_id), None)
        return jsonify(product) if product else (jsonify({"error":"Not found"}),404)

    # Error handlers
    @app.errorhandler(400)
    def bad_request(e): return jsonify({"error":"Bad request"}),400
    @app.errorhandler(401)
    def unauthorized(e): return jsonify({"error":"Unauthorized"}),401
    @app.errorhandler(404)
    def not_found(e): return jsonify({"error":"Not found"}),404
    @app.errorhandler(500)
    def server_error(e): return jsonify({"error":"Server error"}),500

    return app

# Entrypoint
app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    print(f"🚀 Starting on port {port} (debug={debug_mode})")
    
    # Check Supabase connection status
    supabase_status = "✓" if supabase else "✗"
    print(f"Supabase connected: {supabase_status}")
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)