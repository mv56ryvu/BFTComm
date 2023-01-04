includeLinkDOCAx86 := -I/opt/mellanox/doca/include -Wno-deprecated-declarations -L/opt/mellanox/doca/lib/x86_64-linux-gnu
includeLinkDOCAarch := -I/opt/mellanox/doca/include -Wno-deprecated-declarations -L/opt/mellanox/doca/lib/aarch64-linux-gnu
link := -lstdc++ -lpthread -lprotobuf -lucp -lucs -lcrypto -g

BFTComm: BFTComm.cpp ucxclient/ucxclient.cxx crypto/crypto.cxx authenticator.pb.cc peer.pb.cc
	gcc BFTComm.cpp authenticator.pb.cc peer.pb.cc ucxclient/ucxclient.cxx crypto/crypto.cxx $(includeLinkDOCAx86) $(link) -o BFTComm

BFTComm_arch: BFTComm.cpp ucxclient/ucxclient.cxx crypto/crypto.cxx authenticator.pb.cc peer.pb.cc
	gcc BFTComm.cpp authenticator.pb.cc peer.pb.cc ucxclient/ucxclient.cxx crypto/crypto.cxx $(includeLinkDOCAarch) $(link) -o BFTComm

ucxclient: ucxclient/ucxclient.h
	gcc ucxclient/ucxclient.cxx -o ucxclient/ucxclient
	
crypto: crypto/crypto.h
	gcc crypto/crypto.cxx -o crypto/crypto

clean:
	rm -f BFTComm
