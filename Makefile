all:
	$(CC) -o libvirt-wol libvirt-wol.c -lpcap $(shell pkg-config libxml-2.0 --cflags --libs) $(shell pkg-config libvirt --cflags --libs)
