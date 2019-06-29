.PHONY: coverage


coverage:
	coverage report --include="ccnpy/*" --omit="*/test_*"

clean:
	coverage erase
	-coverage run -m unittest

