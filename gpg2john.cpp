/*
 * pgpry - PGP private key recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdlib>
#include <fstream>
#include <iostream>
#include "key.h"
#include "pistream.h"
#include "tester.h"

#include "memblock.h"

using namespace std;

#define N 128

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

enum {
	SPEC_SIMPLE = 0,
	SPEC_SALTED = 1,
	SPEC_ITERATED_SALTED = 3
};

int main(int argc, char **argv)
{
	if(argc < 2) {
		fprintf(stderr, "Usage: %s <GPG Secret Key File>\n", argv[0]);
		exit(-1);
	}

	ifstream inStream;
	inStream.open(argv[1]);
	Key key;
	try {
		PIStream in(inStream);
		in >> key;
	} catch(const std::string & str) {
		std::cerr << "Exception while parsing key: " << str << std::
		    endl;
		return EXIT_FAILURE;
	}
	catch(const char *cstr) {
		std::cerr << "Exception while parsing key: " << cstr << std::
		    endl;
		return EXIT_FAILURE;
	}

	if (!key.locked()) {
		std::
		    cerr << "Err, this secret key doesn't seem to be encrypted"
		    << std::endl;
		return EXIT_FAILURE;
	}
	Tester *t = new Tester(key, NULL);
	t->init();
#define DEBUG
#ifdef DEBUG
	char passphrase[N];
	int l;
#endif
	const String2Key &s2k = key.string2Key();
	printf("%s:$gpg$*%d*%d*%d*", argv[1], key.m_algorithm, key.m_datalen, t->m_bits);
	print_hex(key.m_data, key.m_datalen);
	printf("*%d*%d*%d*%d*%d*", s2k.m_spec, s2k.m_usage, s2k.m_hashAlgorithm, s2k.m_cipherAlgorithm, s2k.bs);
	print_hex(s2k.m_iv, s2k.bs);
	switch(s2k.m_spec) {
		case SPEC_SIMPLE:
			break;
		case SPEC_SALTED:
			printf("*0*");
			print_hex((unsigned char*)s2k.m_salt, 8);

		case SPEC_ITERATED_SALTED:
			printf("*%d*", s2k.m_count);
			print_hex((unsigned char*)s2k.m_salt, 8);
			break;
	}
	printf("\n");

#ifdef DEBUG
	while(fgets(passphrase, N, stdin) != NULL) {
		l = strlen(passphrase);
		passphrase[l-1] = 0;
 		Memblock *b = new Memblock(passphrase);
		try {
			if(t->check(*b)) {
				printf("Password Found : %s\n", passphrase);
				exit(0);
			}
		} catch(const std::string & str) {
		std::cerr << "Exception while parsing key: " << str << std::
		    endl;
		return EXIT_FAILURE;
		}
	}
#endif
	exit(1);
}
