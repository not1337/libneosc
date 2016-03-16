include_HEADERS = libneosc.h
lib_LTLIBRARIES = libneosc.la
libneosc_la_SOURCES = ndefapp.c neoapp.c oathapp.c pbkdf2.c pcsc.c pgpapp.c pivapp.c sha1.c usb.c util.c libneosc.h
libneosc_la_CFLAGS = -Wall -O3 -fomit-frame-pointer `pkg-config --cflags-only-I libpcsclite` `pkg-config --cflags-only-I libusb-1.0` -fPIC
libneosc_la_LDFLAGS = -shared -no-undefined -version-info 0:0:0 -Wl,-x -Wl,-S `pkg-config --libs libpcsclite` `pkg-config --libs libusb-1.0`

install-data-hook:
	rm -f $(libdir)/libneosc.la

