from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_dh_parameters():
    """Gera parâmetros DH que podem ser compartilhados entre clientes"""
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def serialize_dh_parameters(parameters):
    """Serializa parâmetros DH para envio pela rede"""
    return parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )

def deserialize_dh_parameters(param_bytes):
    """Deserializa parâmetros DH recebidos da rede"""
    return serialization.load_pem_parameters(param_bytes, backend=default_backend())

def generate_dh_keypair(parameters):
    """Gera um par de chaves DH usando os parâmetros fornecidos"""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_key(private_key, peer_public_key):
    """Computa a chave compartilhada usando DH"""
    try:
        shared_key = private_key.exchange(peer_public_key)
        return shared_key
    except Exception as e:
        raise Exception(f"Error computing shared key: {str(e)}")

def serialize_dh_public_key(public_key):
    """Serializa chave pública DH para envio - FIXED VERSION"""
    try:
        # Use PEM format which is more reliable for DH keys
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        # Fallback: try DER format
        try:
            return public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as der_e:
            raise Exception(f"Failed to serialize DH public key: PEM error: {e}, DER error: {der_e}")

def deserialize_dh_public_key(key_bytes):
    """Deserializa chave pública DH recebida - FIXED VERSION"""
    try:
        # First try PEM format
        if key_bytes.startswith(b'-----BEGIN PUBLIC KEY-----'):
            return serialization.load_pem_public_key(key_bytes, backend=default_backend())
        else:
            # Try DER format
            return serialization.load_der_public_key(key_bytes, backend=default_backend())
    except Exception as e:
        # Additional debug info
        print(f"Debug: Key bytes length: {len(key_bytes)}")
        print(f"Debug: First 50 bytes: {key_bytes[:50]}")
        print(f"Debug: Key starts with PEM header: {key_bytes.startswith(b'-----BEGIN PUBLIC KEY-----')}")
        raise Exception(f"Failed to deserialize DH public key: {str(e)}")

# Additional helper function for debugging
def validate_dh_key_pair(private_key, public_key, parameters):
    """Validates that a DH key pair is properly formed"""
    try:
        # Test serialization/deserialization cycle
        serialized = serialize_dh_public_key(public_key)
        deserialized = deserialize_dh_public_key(serialized)
        
        # Verify the key can be used for key exchange
        test_private = parameters.generate_private_key()
        shared_key1 = private_key.exchange(test_private.public_key())
        shared_key2 = test_private.exchange(public_key)
        
        print(f" DH key pair validation successful")
        print(f" Serialized key size: {len(serialized)} bytes")
        print(f" Key exchange test: {'PASS' if len(shared_key1) > 0 else 'FAIL'}")
        
        return True
    except Exception as e:
        print(f" DH key pair validation failed: {e}")
        return False