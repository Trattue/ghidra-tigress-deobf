FROM	python:slim

WORKDIR	/gtd

# Dependencies for obfuscation
RUN	apt update
RUN	apt install gcc perl -y

# Build system
RUN	pip install poetry==1.8.3
ENV	POETRY_NO_INTERACTION	1	POETRY_VIRTUALENVS_IN_PROJECT	1	POETRY_VIRTUALENVS_CREATE	1	POETRY_CACHE_DIR	/tmp/poetry_cache

# Project dependencies
COPY	pyproject.toml	poetry.lock	./
RUN	touch README.md
RUN	poetry install --no-root \
	&& rm -rf $POETRY_CACHE_DIR
COPY	src	./src
RUN	poetry install

ENTRYPOINT	[]
