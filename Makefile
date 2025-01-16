help:
	@echo "This project supports the following targets"
	@echo ""
	@echo " make clean - remove unneeded files"
	@echo " make help - show this text"
	@echo " make lint - run flake8"
	@echo " make unittest - run the the unittest"
	@echo ""

blacken:
	@echo "Normalising python layout with black"
	@tox -e black

clean:
	@echo "Cleaning files"
	@git clean -ffXd

lint: blacken
	@echo "Running lint / flake8"
	@tox -e lint

unittest:
	@tox -e unit

.PHONY: clean help lint test unittest
