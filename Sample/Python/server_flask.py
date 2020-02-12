from flask import Flask
import ssl

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World'

if __name__ == '__main__':
    ca_file = "../../Certificates/Root/rootcacert.pem"
    key_file = "../../Certificates/Server/serverkey.pem"
    cert_file = "../../Certificates/Server/servercert.pem"
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile = cert_file, keyfile=key_file)
    context.load_verify_locations(ca_file)
#    context.load_verify_locations(cert_file)
    context.verify_mode = ssl.CERT_REQUIRED
    app.run(debug=True, ssl_context=context)

