# Azul Plugin De4dot

Dotnet deobfuscator based on de4dot, used to be part of netalyser.

## Development Installation

To install azul-plugin-de4dot for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```bash
$ azul-plugin-de4dot malware.file
... example output goes here ...
```

Check `azul-plugin-de4dot --help` for advanced usage.

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Building de4dot

de4dot was built from the github repo https://github.com/kant2002/de4dot

From the release artifacts in an ubuntu maching using the command:

```bash
dotnet build de4dot.netcore.sln  --configuration Release --framework net8.0
```

The entire release directory was then copied into `de4dot_<date-compiled>_netcore8`

NOTE - dotnet 8 was installed first.

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
