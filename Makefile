server:
	gcc milsd.c log.c serverconf.c auth.c parcel.c session.c milssl.c utils.c -o milsd -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -lpam -lpam_misc
client:
	gcc -o mils mils.c utils.c cmdloop.c log.c -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto 
logtest:
	gcc -o logtest logtest.c log.c
gui:
	gcc -Wall -g -o milsgui utils.c milsgui.c log.c cmdloop.c -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto `pkg-config --cflags --libs gtk+-3.0` -export-dynamic
install:
	rm -rf /etc/mils/certs
	mkdir -p /etc/mils/certs/
	openssl req -x509 -newkey rsa:4096 -keyout /etc/mils/certs/key.pem -out /etc/mils/certs/cert.pem -days 365 -nodes
clean:
	rm -rf mils milsd logtest
