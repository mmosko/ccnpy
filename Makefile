.PHONY: coverage


coverage:
	poetry run coverage run -m pytest
	poetry run coverage report -m

check:
	poetry run pytest

clean:
	coverage erase
	-coverage run -m unittest

