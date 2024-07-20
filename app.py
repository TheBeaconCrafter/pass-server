from flask import Flask, request, send_file, jsonify
import json
import zipfile
import hashlib
import OpenSSL
from pathlib import Path
import subprocess
from datetime import datetime
import os
import random
import string

app = Flask(__name__)

# Path to the certificate and key files for signing the pass
certificate_path = "./assets/AppleDevCert.pem"
key_path = "./assets/key.pem"
wwdr_certificate_path = "./assets/WWDRCAG4.pem"  # Correct path to the WWDR certificate

# Path to the certificate and key files for HTTPS
server_certificate_path = "./ssl_certs/bcnlab.org_ssl_certificate.cer"
server_key_path = "./ssl_certs/_.bcnlab.org_private_key.key"

# List of supported asset files
SUPPORTED_ASSET_FILES = [
    "icon.png",
    "icon@2x.png",
    "background.png",
    "background@2x.png",
    "logo.png",
    "logo@2x.png",
    "footer.png",
    "footer@2x.png",
    "strip.png",
    "strip@2x.png",
    "thumbnail.png",
    "thumbnail@2x.png",
]

def generate_pass(pass_data, output_path):
    try:
        # Create a unique directory for temp files
        utc_time = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        temp_dir = Path(f"temp/{utc_time}_{random_suffix}")
        temp_dir.mkdir(parents=True, exist_ok=True)

        # Paths for temporary files
        pass_json_path = temp_dir / "pass.json"
        temp_zip_path = temp_dir / "temp.pkpass"
        manifest_json_path = temp_dir / "manifest.json"
        signature_path = temp_dir / "signature"

        # Create pass.json
        with open(pass_json_path, "w") as f:
            json.dump(pass_data, f, indent=4)  # Added indent for readability

        # Define icon filenames and paths
        icon_source_path = "./default_icons/"

        # Step 1: Create a temporary zip file with pass.json and icons
        with zipfile.ZipFile(temp_zip_path, "w") as zf:
            zf.write(pass_json_path, "pass.json")
            for icon_file in SUPPORTED_ASSET_FILES:
                icon_path = Path(icon_source_path) / icon_file
                if icon_path.is_file():
                    zf.write(icon_path, icon_file)
                else:
                    print(f"Warning: {icon_file} not found in {icon_source_path}")

        # Step 2: Generate manifest.json
        manifest = {}
        with zipfile.ZipFile(temp_zip_path, "r") as zf:
            for file_name in zf.namelist():
                with zf.open(file_name) as f:
                    file_hash = hashlib.sha1(f.read()).hexdigest()
                    manifest[file_name] = file_hash

        with open(manifest_json_path, "w") as f:
            json.dump(manifest, f, indent=4)  # Added indent for readability

        # Step 3: Sign manifest.json using openssl
        command = [
            "openssl", "smime", "-binary", "-sign",
            "-certfile", wwdr_certificate_path,
            "-signer", certificate_path,
            "-inkey", key_path,
            "-in", str(manifest_json_path),
            "-out", str(signature_path),
            "-outform", "DER",
            "-passin", "pass:<key password>"  # Ensure to replace <key password> with actual password
        ]

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error creating signature: {result.stderr}")
            raise Exception("Failed to create signature")

        # Step 4: Create the final .pkpass file
        with zipfile.ZipFile(output_path, "w") as zf:
            # Add files from the temp .pkpass
            with zipfile.ZipFile(temp_zip_path, "r") as temp_zf:
                for file_name in temp_zf.namelist():
                    with temp_zf.open(file_name) as f:
                        zf.writestr(file_name, f.read())

            # Add manifest.json
            zf.write(manifest_json_path, "manifest.json")

            # Add signature
            zf.write(signature_path, "signature")

        # Cleanup temporary files
        for file in temp_dir.glob('*'):
            file.unlink()
        temp_dir.rmdir()

        print(f"Pass created: {output_path}")

    except Exception as e:
        print(f"An error occurred: {e}")

@app.route('/create_pass', methods=['POST'])
def create_pass():
    try:
        pass_data = request.json
        if not pass_data:
            return jsonify({"error": "Invalid JSON data"}), 400

        # Generate a unique file name for the .pkpass
        utc_time = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        temp_dir = Path(f"temp/{utc_time}_{random_suffix}")
        temp_dir.mkdir(parents=True, exist_ok=True)
        output_path = temp_dir / "pass.pkpass"

        generate_pass(pass_data, output_path)
        return send_file(output_path, as_attachment=True, download_name="pass.pkpass")

    except Exception as e:
        print(f"An error occurred while creating the pass: {e}")
        return jsonify({"error": "Failed to create pass"}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, ssl_context=(server_certificate_path, server_key_path))
