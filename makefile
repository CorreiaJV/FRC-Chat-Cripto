client: 
	clear && gcc alice.c -o alice -lm -lcrypto

server:
	clear && gcc bob.c -o bob -lm -lcrypto


client2: 
	clear && gcc alice2.c -o alice -lm -lcrypto

server2:
	clear && gcc bob2.c -o bob -lm -lcrypto