
ifeq ($(origin PYENV_ROOT), undefined)
$(error `pyenv` is required for the Target.)
endif

PYVER := $(lastword $(shell python --version 2>&1))
APPVER := $(strip $(shell cat version))
GITBRANCH := $(strip $(shell git rev-parse --abbrev-ref HEAD))
GITCOMMIT := $(strip $(shell git rev-parse --short HEAD))

all: build

rpm: build
	mkdir -p drmsd-$(APPVER)/bin drmsd-$(APPVER)/etc drmsd-$(APPVER)/etc/init.d
	cp dist/drmsd drmsd-$(APPVER)/bin
	cp drmsd.py drmsd-$(APPVER)
	cp -r etc drmsd-$(APPVER)
	cp build/pyinst-drmsd/base_library.zip drmsd-$(APPVER)/etc
	tar cvzf ~/rpmbuild/SOURCES/drmsd-$(APPVER).tar.gz drmsd-$(APPVER)
	rpmbuild -bb --define "DRMSVER $(APPVER)" --define "GITBRANCH $(GITBRANCH)" --define "GITCOMMIT $(GITCOMMIT)" drms.spec
	rm -rf drmsd-$(APPVER)

TGT=drmsd
rpmclean:	
	rm -rf build dist
	rm -rf drmsd-$(APPVER)
	rm -rf __pycache__
	cp -r ~/rpmbuild/RPMS/x86_64/$(TGT)*$(APPVER)* ./  
	rm -rf ~/rpmbuild/SOURCES/$(TGT)* \
	~/rpmbuild/BUILD/$(TGT)* \
	~/rpmbuild/RPMS/x86_64/$(TGT)* \
	~/rpmbuild/SPEC/$(TGT)* 

build: dist/drmsd

dist/drmsd: distclean
	env LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(PYENV_ROOT)/versions/$(PYVER)/lib/ pyinstaller --onefile pyinst-drmsd.spec

.PHONY: distclean clean

distclean:
	rm -rf build dist
	rm -rf drmsd-$(APPVER)
	rm -rf __pycache__

clean:
	rm -rf build dist
	rm -rf drmsd-$(APPVER)
	rm -rf __pycache__
