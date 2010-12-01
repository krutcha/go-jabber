all:
	make -C pkg install
	make -C example

test:
	make -C pkg test
	make -C example test

clean:
	make -C pkg clean
	make -C example clean

format:
	gofmt -w .
