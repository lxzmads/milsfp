server:
	gcc milsd.c log.c serverconf.c auth.c parcel.c session.c milssl.c utils.c -o milsd -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto 
client:
	gcc -o mils mils.c utils.c lsh.c log.c -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto 
logtest:
	gcc -o logtest logtest.c log.c
install:
	rm -rf /etc/mils/certs
	mkdir -p /etc/mils/certs/
	openssl req -x509 -newkey rsa:4096 -keyout /etc/mils/certs/key.pem -out /etc/mils/certs/cert.pem -days 365 -nodes
clean:
	rm -rf mils milsd logtest