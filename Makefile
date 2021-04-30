lint:
	python -m isort -c -rc checker/checker.py
	python -m black --line-length 160 --check checker/checker.py
	python -m flake8 --select F --per-file-ignores="__init__.py:F401" checker/checker.py
	python -m mypy checker/checker.py

format:
	python -m isort -rc checker/checker.py
	python -m black --line-length 160 checker/checker.py

