# E-commerce Backend API

This is the backend API for the e-commerce application, built with Flask and Supabase.

## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd python-backend
   ```

2. **Create and activate a virtual environment**
   ```bash
   # On Windows
   python -m venv venv
   .\venv\Scripts\activate
   
   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   - Copy `.env.example` to `.env`
   - Fill in your Supabase credentials and other configuration
   ```bash
   cp .env.example .env
   ```

5. **Run the development server**
   ```bash
   python app.py
   ```
   The API will be available at `http://localhost:5000`

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/me` - Get current user profile

### Products

- `GET /api/products` - Get all products
- `GET /api/products/<id>` - Get a specific product

## Environment Variables

- `FLASK_APP` - Flask application entry point
- `FLASK_ENV` - Environment (development/production)
- `SECRET_KEY` - Flask secret key
- `SUPABASE_URL` - Your Supabase project URL
- `SUPABASE_KEY` - Your Supabase anon/public key
- `JWT_SECRET_KEY` - Secret key for JWT tokens
- `CORS_ORIGINS` - List of allowed origins for CORS

## Development

- **Linting**: `flake8 .`
- **Testing**: `pytest`

## Deployment

For production deployment, make sure to:
1. Set `FLASK_ENV=production`
2. Use a production-ready WSGI server (e.g., Gunicorn, uWSGI)
3. Configure a reverse proxy (e.g., Nginx)
4. Set up HTTPS with a valid certificate
