PyMongo Adapter for PyCasbin
====

[![build Status](https://github.com/officialpycasbin/pymongo-adapter/actions/workflows/main.yml/badge.svg)](https://github.com/officialpycasbin/pymongo-adapter/actions/workflows/main.yml)
[![Coverage Status](https://coveralls.io/repos/github/officialpycasbin/pymongo-adapter/badge.svg)](https://coveralls.io/github/officialpycasbin/pymongo-adapter)
[![Version](https://img.shields.io/pypi/v/casbin_pymongo_adapter.svg)](https://pypi.org/project/casbin_pymongo_adapter/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/casbin_pymongo_adapter.svg)](https://pypi.org/project/casbin_pymongo_adapter/)
[![Pyversions](https://img.shields.io/pypi/pyversions/casbin_pymongo_adapter.svg)](https://pypi.org/project/casbin_pymongo_adapter/)
[![Download](https://static.pepy.tech/badge/casbin_pymongo_adapter)](https://pypi.org/project/casbin_pymongo_adapter/)
[![License](https://img.shields.io/pypi/l/casbin_pymongo_adapter.svg)](https://pypi.org/project/casbin_pymongo_adapter/)

PyMongo Adapter is the [PyMongo](https://pypi.org/project/pymongo/) adapter for [PyCasbin](https://github.com/casbin/pycasbin). With this library, Casbin can load policy from MongoDB or save policy to it.

This adapter supports both synchronous and asynchronous PyMongo APIs.

## Installation

```
pip install casbin_pymongo_adapter
```

## Simple Example

```python
import casbin_pymongo_adapter
import casbin

adapter = casbin_pymongo_adapter.Adapter('mongodb://localhost:27017/', "dbname")

e = casbin.Enforcer('path/to/model.conf', adapter, True)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1casbin_sqlalchemy_adapter
    pass
else:
    # deny the request, show an error
    pass

# define filter conditions
from casbin_pymongo_adapter import Filter

filter = Filter()
filter.ptype = ["p"]
filter.v0 = ["alice"]

# support MongoDB native query
filter.raw_query = {
    "ptype": "p",
    "v0": {
        "$in": ["alice"]
    }
}

# In this case, load only policies with sub value alice
e.load_filtered_policy(filter)
```

## Async Example

```python
from casbin_pymongo_adapter.asynchronous import Adapter
import casbin

adapter = Adapter('mongodb://localhost:27017/', "dbname")
e = casbin.AsyncEnforcer('path/to/model.conf', adapter)

# Note: AsyncEnforcer does not automatically load policies.
# You need to call load_policy() manually.
await e.load_policy()
```


### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
