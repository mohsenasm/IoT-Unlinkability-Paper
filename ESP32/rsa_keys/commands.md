openssl genrsa -out key.pem 2048
openssl rsa -in key.pem -outform PEM -pubout -out public.pem
openssl base64 -d -in public.pem -out pubkey.der
