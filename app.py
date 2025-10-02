"""
API name: solidals
Author: brynrefill
Description: ...
Contact: info@brynrefill.com
"""

from flask import Flask, jsonify

app = Flask(__name__)

# endpoints
@app.route('/', methods=['GET'])
def doc():
    """API documentation endpoint"""
    return jsonify({
        "message": "...",
        "endpoints": {
            "GET /": "API documentation",
            "...": "..."
        }
    })

# errors handling
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found!"}), 404

# main
if __name__ == '__main__':
    print("\nStarting solidals API...")
    print("\nAvailable endpoints:")
    print("  GET / - API documentation")
    print("\nExample usage:")
    print("  curl -X GET http://localhost:5000/\n")

    app.run(debug=True, host='0.0.0.0', port=5000)
