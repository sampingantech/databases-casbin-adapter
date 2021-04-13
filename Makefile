test:
	mkdir -p outputs
	python -W ignore::DeprecationWarning -m pytest --cov-config=.coveragerc --cov=app --cov-report xml:outputs/coverage.xml -v -s $(test)

install:
	pip install -r requirements.txt
	pip install -r requirements-test.txt
