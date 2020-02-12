import urllib.request
import ssl

if __name__=='__main__':
    ca_file = "../../Certificates/Root/rootcacert.pem"
    key_file = "../../Certificates/Client/clientkey.pem"
    cert_file = "../../Certificates/Client/clientcert.pem"

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.check_hostname = False
    context.load_cert_chain(certfile = cert_file, keyfile=key_file)
    context.load_verify_locations(ca_file)
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        request = urllib.request.Request('https://127.0.0.1:5000/')
        res = urllib.request.urlopen(request, context = context)
        print(res.code)
        print(res.read().decode("utf-8"))
    except Exception as ex:
        print("find error in auth phase:%s" % str(ex))
