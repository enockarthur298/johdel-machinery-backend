from flask import Flask, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Sample data
products = [
    {"id": 1, "name": "Cordless Drill", "price": 129.99, "inStock": True},
    {"id": 2, "name": "Circular Saw", "price": 149.99, "inStock": True},
    {"id": 3, "name": "Hammer Drill", "price": 179.99, "inStock": False}
]

# Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "message": "API is running"})

@app.route('/api/products', methods=['GET'])
def get_products():
    return jsonify({"products": products})

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = next((p for p in products if p['id'] == product_id), None)
    if product:
        return jsonify(product)
    return jsonify({"error": "Product not found"}), 404

# Start the server
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
