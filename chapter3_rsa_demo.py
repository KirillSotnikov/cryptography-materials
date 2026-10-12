from pathlib import Path
import base64, hashlib, json
import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
BASE=Path(__file__).resolve().parent
ORIGINAL=BASE/'synthetic_transcript_original.txt'
MODIFIED=BASE/'synthetic_transcript_modified.txt'
PUBLIC_KEY=BASE/'rsa_public_key.pem'
SIGNATURE_BIN=BASE/'transcript_signature.bin'
SIGNATURE_B64=BASE/'transcript_signature.b64.txt'
RESULTS_JSON=BASE/'rsa_demo_results.json'
OUTPUT_TXT=BASE/'rsa_demo_output.txt'
RSA_KEY_SIZE=3072
HASH_ALGORITHM=hashes.SHA256()
PSS_PADDING=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size)
def sha256_hex(data): return hashlib.sha256(data).hexdigest()
def verify(public_key, signature, data):
    try:
        public_key.verify(signature, data, PSS_PADDING, HASH_ALGORITHM)
        return True
    except InvalidSignature:
        return False

def main():
    original_data=ORIGINAL.read_bytes()
    private_key=rsa.generate_private_key(public_exponent=65537,key_size=RSA_KEY_SIZE)
    public_key=private_key.public_key()
    PUBLIC_KEY.write_bytes(public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
    signature=private_key.sign(original_data,PSS_PADDING,HASH_ALGORITHM)
    SIGNATURE_BIN.write_bytes(signature)
    SIGNATURE_B64.write_text(base64.b64encode(signature).decode('ascii')+'\n')
    text=original_data.decode('utf-8')
    modified_text=text.replace('Final Grade: B+','Final Grade: A',1)
    MODIFIED.write_text(modified_text,encoding='utf-8')
    modified_data=MODIFIED.read_bytes()
    original_correct_key=verify(public_key,signature,original_data)
    modified_original_signature=verify(public_key,signature,modified_data)
    unrelated_private_key=rsa.generate_private_key(public_exponent=65537,key_size=RSA_KEY_SIZE)
    original_wrong_key=verify(unrelated_private_key.public_key(),signature,original_data)
    results={
      'library':f'cryptography {cryptography.__version__}',
      'signature_scheme':'RSA-PSS','rsa_key_size_bits':RSA_KEY_SIZE,'hash_algorithm':'SHA-256',
      'original_sha256':sha256_hex(original_data),'modified_sha256':sha256_hex(modified_data),
      'tests':{
        'original_file_correct_public_key':original_correct_key,
        'modified_file_original_signature':modified_original_signature,
        'original_file_unrelated_public_key':original_wrong_key},
      'private_key_saved_to_disk':False}
    RESULTS_JSON.write_text(json.dumps(results,indent=2)+'\n')
    lines=[
      'MSIT 5270 - RSA Digital Signature Demonstration',
      '================================================',
      f'Library: cryptography {cryptography.__version__}',
      'Signature scheme: RSA-PSS',f'RSA key size: {RSA_KEY_SIZE} bits','Hash algorithm: SHA-256','',
      f"Original SHA-256: {results['original_sha256']}",
      f"Modified SHA-256: {results['modified_sha256']}",'',
      f"[{'PASS' if original_correct_key else 'FAIL'}] Original transcript + correct public key: {'signature verified' if original_correct_key else 'verification failed'}",
      f"[{'PASS' if not modified_original_signature else 'FAIL'}] Modified transcript + original signature: {'verification correctly failed' if not modified_original_signature else 'UNEXPECTED verification success'}",
      f"[{'PASS' if not original_wrong_key else 'FAIL'}] Original transcript + unrelated public key: {'verification correctly failed' if not original_wrong_key else 'UNEXPECTED verification success'}",
      '', 'Private key saved to disk: NO (lab key remained in memory)','Synthetic data only: YES']
    output='\n'.join(lines)+'\n'
    OUTPUT_TXT.write_text(output)
    print(output,end='')
if __name__=='__main__': main()
