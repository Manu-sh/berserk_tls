# berserk_tls

#### generate key.pem & cert.pem
you can read more [here](https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs#generate-a-self-signed-certificate)

`openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out crt.pem`


#### server
use an openssl server to test the client

`openssl s_server -cert crt.pem -key key.pem -port 5000 -CAfile crt.pem -verify_return_error -Verify 1`

#### client
use an openssl client to test the server

`openssl s_client -cert crt.pem -key key.pem -CAfile crt.pem -connect localhost:5000`

`curl -k --cert crt.pem --key key.pem https://localhost:5000/sad`

##### the first (testing ssl) is most important
- https://stackoverflow.com/questions/21050366/testing-ssl-tls-client-authentication-with-openssl
- https://stackoverflow.com/questions/17024769/openssl-client-not-sending-client-certificate

##### other resources
- https://knowledge.digicert.com/tutorials/create-pem-file-for-tls-ssl-certificate-installations
