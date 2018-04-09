DESTDIR := 
PREFIX := /usr/local


install: pa.py
	install -D pa.py $(DESTDIR)$(PREFIX)/bin/pa
