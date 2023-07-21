client: 
	clear && gcc alice.c -o alice -lm -lcrypto && ./alice

server:
	clear && gcc bob.c -o bob -lm -lcrypto && ./bob


client2: 
	clear && gcc alice2.c -o alice -lm -lcrypto

server2:
	clear && gcc bob2.c -o bob -lm -lcrypto