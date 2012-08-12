target:
	g++ -Wall -ggdb gpg2john.cpp tester.cpp pistream.cpp key.cpp string2key.cpp packetheader.cpp utils.cpp cryptutils.cpp -lcrypto -o gpg2john
