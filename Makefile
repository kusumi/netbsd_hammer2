SUBDIRS = src

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@; \
	done
	find src/ -type f -name "*.html8" | xargs rm
install:
	sudo bash -x ./script/install.sh
uninstall:
	sudo bash -x ./script/uninstall.sh
