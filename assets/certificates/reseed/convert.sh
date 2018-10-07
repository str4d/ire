#!/bin/sh
# Convert to the binary RSAPublicKey format needed by the ring crate
for cert in *.crt
do
    pem=$(echo $cert | sed 's/\(.*\.\)crt/\1pem/')
    der=$(echo $cert | sed 's/\(.*\.\)crt/\1der/')
    openssl x509 -pubkey -noout -in $cert -out $pem
    openssl rsa -pubin -in $pem -inform pem -RSAPublicKey_out -out $der -outform der
    rm $pem
done
