from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
import io
import stego_engine
from PIL import Image

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/encode', methods=['POST'])
def encode_api():
    if 'image' not in request.files:
        return jsonify({"success": False, "error": "Missing image file"}), 400
    file = request.files['image']
    message = request.form.get('message', '')
    password = request.form.get('password', '')

    if not message or not password:
        return jsonify({"success": False, "error": "Missing fields"}), 400
        try:
            img = Image.open(file.stream)
            max_dimensions = (1200, 1200)
            if img.width > 1200 or img.height > 1200:
                img.thumbnail(max_dimensions, Image.Resampling.LANCZOS)
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG')
            raw_bytes = img_byte_arr.getvalue()
            output_png = stego_engine.encode_image(raw_bytes, message, password)
            return send_file(
                io.BytesIO(output_png),
                mimetype='image/png',
                as_attachment=True,
                download_name='encrypted_stego.png'
            )
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/decode', methods=['POST'])
def decode_api():
    if 'image' not in request.files:
        return jsonify({"success": False, "error": "Missing image file"}), 400

    file = request.files['image']
    password = request.form.get('password', '')

    if not password:
        return jsonify({"success": False, "error": "Password input empty"}), 400

    try:
        raw_bytes = file.read()
        extracted_message = stego_engine.decode_image(raw_bytes, password)
        return jsonify({"success": True, "message": extracted_message})
    except Exception:
        return jsonify({"success": False, "error": "Decryption failed. Bad password or clean image."}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
