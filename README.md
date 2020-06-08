# berserk_tls

#### server
`openssl s_server -cert crt.pem -key key.pem -port 5000 -CAfile crt.pem -verify_return_error -Verify 1`

#### client
`openssl s_client -cert crt.pem -key key.pem -CAfile crt.pem -connect localhost:5000`
`curl -k --cert crt.pem --key key.pem https://localhost:5000/sad`

##### the first (testing ssl) is most important
https://stackoverflow.com/questions/21050366/testing-ssl-tls-client-authentication-with-openssl
https://stackoverflow.com/questions/17024769/openssl-client-not-sending-client-certificate
