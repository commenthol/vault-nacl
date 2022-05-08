engines = 12 14 18 16

.PHONY: all
all: engines

.PHONY: engines
engines: $(engines)

.PHONY: $(engines)
$(engines):
	@ n $@
	@ $(MAKE) test

.PHONY: test
test:
	@ npm test
