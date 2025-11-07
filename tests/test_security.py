from app.core.security import hash_password, verify_password, encrypt_secret, decrypt_secret

def test_security():
    password = "StrongPass123!"
    pw_hash = hash_password(password)
    assert verify_password(password, pw_hash)

    enc_key = encrypt_secret(password, "api_key_example")
    dec_key = decrypt_secret(password, enc_key)
    assert dec_key == "api_key_example"

if __name__ == "__main__":
    test_security()
    print("ok")
