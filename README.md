Practical API Security Example
==============================

This repository consists of client and server code comprising the example
material for Practical API Security.

Installing
----------

### Pre-Installation Requirements

* [Git](https://git-scm.com/downloads)
* [Python 3.6](https://www.python.org/downloads/release)
* [PIP](https://pip.pypa.io/en/stable/installing/)

### Clone This Repository

Clone this repository to your computer

```bash
git clone https://github.com/aenglander/practical-api-security-python-example-flask.git
```

### Setup Virtual Environment (Optional)

Optionally, you can set up a virtual environment for the demo application to prevent the demo from interfering
with your other Python applications. Instructions can be found here:
[Creating Virtual Environments](https://docs.python.org/3/tutorial/venv.html#creating-virtual-environments).

### Installing Requirements

Run a PIP install with the [requirements](requirements.txt) file:

```bash
pip install -r requirements.txt
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

