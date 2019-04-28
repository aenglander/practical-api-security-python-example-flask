Practical API Security Example
==============================

This repository consists of client and server code comprising the example
material for Practical API Security.

Installing
----------

### Pre-Installation Requirements

* [Git](https://git-scm.com/downloads)
* [Python 3.6](https://www.python.org/downloads/release)
* [pipenv](https://docs.pipenv.org/install/#installing-pipenv)

### Clone This Repository

Clone this repository to your computer

```bash
git clone https://github.com/aenglander/practical-api-security-python-example-flask.git
```

### Installing Requirements and Virtual Environment

Run a pipenv install:

```bash
pipenv install
```

### Start Virtual Environment

Start a pipenv shell:

```bash
pipenv shell
```

### Verifying the installation

1. Start the server

    From Bash:
    ```bash
    export FLASK_APP=server.py
    export FLASK_ENV=development
    flask run
    ```
    
    From Windows:
    ```
    set FLASK_APP=server.py
    set FLASK_ENV=development
    flask run
    ```

1. Run the client:

    ```bash
    python client.py
    ```
    
1. The client response should be:

    ```
    REQUEST:
    
    === No Request ===
    
    RESPONSE:
    
    Decrypted Body:
    {
      "Hello": "World!"
    }
    ```
