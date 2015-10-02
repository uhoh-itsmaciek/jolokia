* Use the following `jolokia.properties` to enable SSL authentication. 
  Adapt the path accordingly to the certs found in this directory:
 
```
protocol=https
caCert=cacert.pem
serverCert=servercert.pem
serverKey=jserverkey.pem
useSslClientAuthentication=true
discoveryEnabled=false
port=8778
host=0.0.0.0
```

* Then start process with Jolokia attached:

```
java -javaagent:jolokia.jar=config=jolokia.properties
```

* Import client certificate `client.p12` (or you could try it with `server.p12`, too)

* Start Java server and then go to `https://localhost:8778/jolokia/` with the browser (trailing slash important)

# Passwords

* CA Key `cakey.pem`  : "1234"
* CA Cert `client.key` : "1234"
* Client Cert `client.p12` : "1234" 
* Server Key `serverkey.pem` : No password
* Server Key as P12 `server.p12` : Password: "1234"

# Howto create certs

```
# Start an Open SSL container
docker run -it -v `pwd`:/tmp/ 

# Create CA Key
openssl genrsa -des3 -out cakey.pem 4096
openssl req -new -x509 -days 3650 -key cakey.pem -out cacert.pem

# Create a Server Key & signing request & sign it (with no password on the key)
openssl genrsa -out serverkey.pem -aes128 2048 -days 3650
openssl rsa -in serverkey.pem -out serverkey.pem
openssl req -new -key serverkey.pem -out server.csr -nodes
openssl x509 -req -days 3650 -in server.csr -CA cacert.pem -CAkey cakey.pem -set_serial 01 -out servercert.pem

# Create a Client Key & signing request & sign it
openssl genrsa -des3 -out clientkey.pem 4096
openssl req -new -key clientkey.pem -out client.csr
openssl x509 -req -days 3650 -in client.csr -CA cacert.pem -CAkey cakey.pem -set_serial 02 -out clientcert.pem

# Convert client key to PKCS
openssl pkcs12 -export -clcerts -in clientcert.pem -inkey clientkey.pem -out client.p12

# Import client key to Browser
```