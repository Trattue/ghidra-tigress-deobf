FROM	python:slim

WORKDIR	/gtd
RUN	apt update
RUN	apt install gcc perl -y
RUN	pip install poetry
ENV	POETRY_NO_INTERACTION	1	POETRY_VIRTUALENVS_IN_PROJECT	1	POETRY_VIRTUALENVS_CREATE	1	POETRY_CACHE_DIR	/tmp/poetry_cache
COPY	pyproject.toml	poetry.lock	./
RUN	touch README.md
RUN	poetry install --no-root \
	&& rm -rf $POETRY_CACHE_DIR
COPY	.	.
RUN	poetry install
ENTRYPOINT	["poetry","run"]
CMD	["main","samples/samplea.toml"]
