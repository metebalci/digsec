clean:
	rm -rf dist

sdist: clean
	python setup.py sdist

pylint: 
	pylint digsec/*.py

upload:
	twine upload dist/*
