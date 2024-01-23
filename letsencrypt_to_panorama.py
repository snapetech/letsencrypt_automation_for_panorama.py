import os
import pandas as pd
import subprocess
import secrets
import string
import logging
import requests
import xml.etree.ElementTree as ET
from datetime import datetime

# Constants
ACME_SH_PATH = './acme.sh'
ACME_SERVER_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'  # remove -staging- for production environment
KEY_LENGTH = '2048'
LOG_FILE = 'acme_certificate_generation.log'
EXCEL_FILE_PATH = 'hosts.xlsx'

# Panorama Constants
FIREWALL_NAME = 'panorama.domain.com'
API_KEY = 'panorama_api'

def generate_passphrase():
    characters = string.ascii_letters + string.digits
    passphrase = ''.join(secrets.choice(characters) for _ in range(16))
    return passphrase

def run_command(command, domain):
    try:
        subprocess.run(command, check=True, text=True)
        logging.info(f"Successfully executed command for {domain}: {command}")
    except subprocess.CalledProcessError as e:
        logging.exception(f"Command failed for {domain}: {command}. Error: {e}")

def generate_certificate(domain):
    logging.info(f"Generating new certificate for {domain}...")
    generate_command = [
        ACME_SH_PATH,
        '--issue',
        '--dns', 'dns_gd',
        '--domain', domain,
        '--keylength', KEY_LENGTH,
        '--server', ACME_SERVER_URL,
        '--force'
    ]
    run_command(generate_command, domain)

def get_existing_certificates(firewall_name, api_key, template):
    base_url = f"https://{firewall_name}/api/"
    xpath = f"/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='{template}']/config/shared/certificate"
    params = {
        "key": api_key,
        "type": "config",
        "action": "get",
        "xpath": xpath
    }
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        xml_response = response.text
        root = ET.fromstring(xml_response)
        
        # Convert XML ElementTree object to string
        xml_string = ET.tostring(root, encoding='utf-8').decode('utf-8')
        
        # Log and print the XML string
        logging.info(f"Retrieved certificates data: {xml_string}")
        print(f"Retrieved certificates data: {xml_string}")
        
        return root
    except requests.HTTPError as e:
        logging.exception(f"Failed to retrieve certificates. HTTPError: {e}")
    except ET.ParseError as e:
        logging.exception(f"Failed to parse XML. ParseError: {e}")
    except Exception as e:
        logging.exception(f"Failed to retrieve certificates. Error: {e}")
    return None

def delete_existing_keys_from_panorama(domain, template):
    base_url = f"https://{FIREWALL_NAME}/api/"
    cert_name = domain.split(".domain.com")[0]
    #certificate_entries = certificates_data.get('response', {}).get('result', {}).get('certificate', {}).get('entry', []) if certificates_data else []

    # Code for deleting keys regardless of whether certificates were found
    # Construct XPath for deleting private key, public key, and certificate entry
    private_key_xpath = f"/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='{template}']/config/shared/certificate/entry[@name='{cert_name}']/private-key"
    public_key_xpath = f"/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='{template}']/config/shared/certificate/entry[@name='{cert_name}']/public-key"
    certificate_entry_xpath = f"/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='{template}']/config/shared/certificate/entry[@name='{cert_name}']"

    # Delete the private key
    private_key_payload = {
        "key": API_KEY,
        "type": "config",
        "action": "delete",
        "xpath": private_key_xpath
    }
    # Delete the public key
    public_key_payload = {
        "key": API_KEY,
        "type": "config",
        "action": "delete",
        "xpath": public_key_xpath
    }
    # Delete the certificate entry itself
    certificate_entry_payload = {
        "key": API_KEY,
        "type": "config",
        "action": "delete",
        "xpath": certificate_entry_xpath
    }
    try:
        # Delete the private key
        response_private = requests.post(base_url, data=private_key_payload)
        response_private.raise_for_status()
        if 'status="success"' in response_private.text:
            logging.info(f"Private key for {cert_name} deleted successfully.")
        else:
            if 'error' in response_private.text.lower():
                logging.error(f"Error in API response when deleting private key for {cert_name}: {response_private.text}")
            else:
                logging.error(f"Failed to delete private key for {cert_name}. API Response: {response_private.text}")

        # Delete the public key
        response_public = requests.post(base_url, data=public_key_payload)
        response_public.raise_for_status()
        if 'status="success"' in response_public.text:
            logging.info(f"Public key for {cert_name} deleted successfully.")
        else:
            if 'error' in response_public.text.lower():
                logging.error(f"Error in API response when deleting public key for {cert_name}: {response_public.text}")
            else:
                logging.error(f"Failed to delete public key for {cert_name}. API Response: {response_public.text}")

        # Delete the certificate entry itself
        response_cert_entry = requests.post(base_url, data=certificate_entry_payload)
        response_cert_entry.raise_for_status()
        if 'status="success"' in response_cert_entry.text:
            logging.info(f"Certificate entry for {cert_name} deleted successfully.")
        else:
            if 'error' in response_cert_entry.text.lower():
                logging.error(f"Error in API response when deleting certificate entry for {cert_name}: {response_cert_entry.text}")
            else:
                logging.error(f"Failed to delete certificate entry for {cert_name}. API Response: {response_cert_entry.text}")
    except requests.HTTPError as e:
        logging.exception(f"Failed to delete keys for {cert_name}. HTTPError: {e}")
    except Exception as e:
        logging.exception(f"Failed to delete keys for {cert_name}. Error: {e}")

def encrypt_private_key(domain, passphrase):
    private_key_path = os.path.expanduser(f'~/.acme.sh/{domain}/{domain}.key')
    encrypted_key_path = os.path.expanduser(f'~/.acme.sh/{domain}/encrypted_privkey.key')
    encrypt_command = [
        'openssl', 'rsa',
        '-in', private_key_path,
        '-out', encrypted_key_path,
        '-aes256', '-passout', f'pass:{passphrase}'
    ]
    run_command(encrypt_command, domain)

def set_certificate_name_on_panorama(domain, template):
    base_url = f"https://{FIREWALL_NAME}/api/"
    cert_name = domain.split(".domain.com")[0]
    payload = {
        "key": API_KEY,
        "type": "config",
        "action": "set",
        "xpath": f"/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='{template}']/config/shared/certificate/entry[@name='{cert_name}']/common-name",
        "element": f"<common-name>{domain}</common-name>"
    }
    logging.info(f"Setting certificate name for {cert_name} on Panorama...")
    try:
        response = requests.post(base_url, data=payload)
        response.raise_for_status()
        if 'status="success"' in response.text:
            logging.info(f"Certificate name set successfully for {cert_name}: {response.text}")
        else:
            if 'error' in response.text.lower():
                logging.error(f"Error in API response when setting certificate name for {cert_name}: {response.text}")
            else:
                logging.error(f"Failed to set certificate name for {cert_name}. API Response: {response.text}")
    except requests.HTTPError as e:
        logging.exception(f"Failed to set certificate name for {cert_name}. HTTPError: {e}")
    except Exception as e:
        logging.exception(f"Failed to set certificate name for {cert_name}. Error: {e}")

def upload_file_to_panorama(domain, filename, category, template, passphrase=None):
    base_url = f"https://{FIREWALL_NAME}/api/"
    cert_name = domain.split(".domain.com")[0]
    payload = {
        "key": API_KEY,
        "type": "import",
        "category": category,
        "certificate-name": cert_name,
        "format": "pem",
        "target-tpl": template
    }

    if passphrase:
        payload['passphrase'] = passphrase

    filepath = os.path.expanduser(f'~/.acme.sh/{domain}/{filename}')
    
    if os.path.exists(filepath):
        files = {'file': open(filepath, 'rb')}
        try:
            response = requests.post(base_url, data=payload, files=files)
            response.raise_for_status()
            if 'status="success"' in response.text:
                logging.info(f"File {filename} uploaded successfully for {cert_name}: {response.text}")
            else:
                if 'error' in response.text.lower():
                    logging.error(f"Error in API response when uploading {filename} for {cert_name}: {response.text}")
                else:
                    logging.error(f"Failed to upload {filename} for {cert_name}. API Response: {response.text}")
        except requests.HTTPError as e:
            logging.exception(f"Failed to upload {filename} for {cert_name}. HTTPError: {e}")
        except Exception as e:
            logging.exception(f"Failed to upload {filename} for {cert_name}. Error: {e}")
    else:
        logging.warning(f"File {filename} does not exist for {cert_name}. Skipping upload.")

def setup_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    root_logger.addHandler(console_handler)

def main():
    setup_logging()
    try:
        df = pd.read_excel(EXCEL_FILE_PATH, header=None)
        domains = df.iloc[:, 0].tolist()
        templates = df.iloc[:, 1].tolist()
    except Exception as e:
        logging.exception(f"Failed to read Excel file. Error: {e}")
        return

    for index, domain in enumerate(domains):
        template = templates[index]
        passphrase = generate_passphrase()

        certificates_data = get_existing_certificates(FIREWALL_NAME, API_KEY, template)

        generate_certificate(domain)
        encrypt_private_key(domain, passphrase)
        delete_existing_keys_from_panorama(domain, template)
        #set_certificate_name_on_panorama(domain, template)
        upload_file_to_panorama(domain, 'fullchain.cer', 'certificate', template)
        upload_file_to_panorama(domain, 'encrypted_privkey.key', 'private-key', template, passphrase)

if __name__ == "__main__":
    main()
