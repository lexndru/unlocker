CWD=$(shell pwd)
SRC_DIR=unlocker

.PHONY: all clean build lint tests

all: clean lint build

build: lint tests
	cd /tmp && virtualenv $(SRC_DIR) && cd $(SRC_DIR)
	cp -R $(CWD) /tmp/$(SRC_DIR)
	ls -l

clean:
	find . -regextype posix-extended -regex ".*.pyc" -type f -delete
	rm -rf /tmp/$(SRC_DIR)

release: build
	cd /tmp/$(SRC_DIR)/$(SRC_DIR) && python setup.py sdist
	ls -l

lint:
	flake8 $(SRC_DIR)

tests:
	python -m unittest discover -v tests
