import subprocess

def generate_aes_key(path="aes.key"):
    subprocess.run(["openssl", "rand", "-out", path, "32"], check=True)
    with open(path, "rb") as f:
        key_content = f.read()
    return key_content.hex()
def encrypt_file_openssl(input_file, output_file, key_path):
    subprocess.run([
        "openssl", "enc", "-aes-256-cbc", "-in", input_file, "-out", output_file,
        "-pass", f"file:{key_path}", "-pbkdf2"
    ], check=True)
def generate_rsa_keys(private_key_path="private.pem", public_key_path="public.pem"):
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", private_key_path, "-pkeyopt", "rsa_keygen_bits:2048"], check=True)
    subprocess.run(["openssl", "rsa", "-in", private_key_path, "-pubout", "-out", public_key_path], check=True)

    with open(public_key_path, "r") as f:
        public_key = f.read()
    return public_key
def encrypt_small_file_rsa(input_file, output_file, public_key_path):
    subprocess.run([
        "openssl", "rsautl", "-encrypt", "-inkey", public_key_path,
        "-pubin", "-in", input_file, "-out", output_file
    ], check=True)
