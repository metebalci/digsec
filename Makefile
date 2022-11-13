
all: clean
	python setup.py sdist

clean:
	rm -rf dist

upload:
	twine upload dist/*
