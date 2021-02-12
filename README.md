signal-protocol-python
======================

DISCLAMER: Incomplete and untrusthworthy python bindings for
libsignal-protocol-c. These bindings were used for academic research purposes
and should not be used in real world cryptographic applications.

Python 3 bindings for *libsignal-protocol-c*. The actual c code is integrated
using the *C Foreign Function Interface for Python* package.

Get Started
-----------

### Get Source
```
> git clone git@github.com:cholin/libsignal-protocol-python.git
> git submodule update --init --recursive
```

### Build libsignal-protocol-c as library
```
> cd libs/libsignal-protocol-c
> mkdir build && make
> cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
> make
> cd ../..
```

### Create environment and install dependencies
```
> python -m venv env
> . env/bin/activate
> pip install -r requirements.txt
```

### Start tests
```
pytest -s
```
