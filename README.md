# PyCrypto Example Code
Example encryption code using Python and the PyCrypto module.

Currently has one module, `logfileio.py`, that writes and reads to
an encrypted file with authentication. Uses AES encryption in
counter mode and HMAC for authentication. Full details of the code
can be found in this blog
[post](http://stevenwooding.com/python-example-encryption-using-aes-in-counter-mode/).

This code was written for the Coursera Cybersecurity Capstone Project course. It
survived being attacked by other students on the course, but this does not mean
that it is bug free. Use with caution.

## Required Libraries and Dependencies

Python 2.x is required to run this project. The Python executable should be in
your default path, which the Python installer should have set.

PyCrypto 2.6.1 module is required. Please follow the installation instructions
on the PyCrypto package page [here](https://pypi.python.org/pypi/pycrypto).

## How to Run

Download the project zip file to you computer and unzip the file. Or clone this
repository to your desktop.

Open the text-based interface for your operating system (e.g. the terminal
window in Linux, the command prompt in Windows).

Navigate to the project directory and type in the following command:

```bash
python logfileio.py
```

This will run the built-in test harness for the module. If you would like to use
the module in your own code, import the module as usual.

