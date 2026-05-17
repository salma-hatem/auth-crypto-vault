.PHONY: build test bench demo demo-tamper gui clean help

PYTHON ?= python3
NATIVE_DIR := aes_v2/native
NATIVE_LIB := $(NATIVE_DIR)/libaes_v2.so

help:
	@echo "Targets:"
	@echo "  build         - compile the AES V2 C extension ($(NATIVE_LIB))"
	@echo "  test          - run the test suite (unittest discover)"
	@echo "  demo          - ~10 s end-to-end demo (NIST + V1/V2 timing + tamper)"
	@echo "  bench         - full 5 MB V1 vs V2 benchmark (slow: V1 takes minutes)"
	@echo "  demo-tamper   - just the bit-flip tamper-rejection script"
	@echo "  gui           - launch the browser GUI (requires: pip install flask)"
	@echo "  clean         - remove build artifacts"

build: $(NATIVE_LIB)

$(NATIVE_LIB):
	$(MAKE) -C $(NATIVE_DIR)

test:
	$(PYTHON) -m unittest discover -s tests -v

demo: build
	$(PYTHON) -u bench/demo.py

bench: build
	$(PYTHON) -u bench/bench.py --size 5MB --runs 3 | tee bench/bench-5mb.txt

demo-tamper: build
	$(PYTHON) bench/demo_tamper.py

gui: build
	$(PYTHON) gui/server.py

clean:
	$(MAKE) -C $(NATIVE_DIR) clean
	find . -type d -name __pycache__ -exec rm -rf {} +
