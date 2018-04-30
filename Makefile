DESTDIR := 
PREFIX := /usr/local


install: pa.py
	install -D pa.py $(DESTDIR)$(PREFIX)/bin/pa
	install -D -m644 complete/pa.sh $(DESTDIR)$(PREFIX)/share/bash-completion/completions/pa
