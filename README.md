# WebHashcat
Hashcat web interface

WebHashcat is a very simple but efficient web interface for hashcat password cracking tool.
It hash the following features:
* Distributed cracking sessions between multiple server (you only need to install HashcatNode on the remote server)
* Cracked hashes are displayed as soon as they are cracked
* Analytics

Currently WebHashcat supports rule-based and mask-based attack mode

This project is composed of 2 parts: 
- WebHashcat, the web interface made with the django framework 
- HashcatNode, A hashcat wrapper with creates an API over hashcat

## Usage

To be done

## Install

### HashcatNode

Rename the settings.ini.sample file to settings.ini and fill the parameters accordingly.

The rules, mask and wordlist directory must be writable by the user running hashcatnode

the hashcatnode can be run simply by running `./hashcatnode.py`

#### Dependencies

- python3
- flask
- flask-basicauth
- hashcat >= 3

### WebHashcat

#### Configuration

WebHashcat is a django application using mysql database, its installation is done this way:
* Edit `WebHashcat/settings.py` file:
- Change the SECRET_KEY parameter
- Add your webhashcat fqdn to ALLOWED_HOSTS
- Set your mysql username and password in the DATABASES section
- Set DEBUG = False if you are using it in production !
you can refer to the following django documentation for further info: https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

* Edit `settings.ini` file
- the potfile parameter doesn't need to be changed

* Create the database with django
```
./manage.py makemigrations
./manage.py migrate
```

* Create the user to access the interface
```
./manage.py createsuperuser
```

#### Setting up the web server

* If you want to test the interface without setting up a web server use this command:
```
./manage.py runserver
```

* If you want to set up the interface with a proper webserver like apache or nginx please refer to the following documentation:
https://docs.djangoproject.com/en/2.0/howto/deployment/wsgi/modwsgi/

#### Setting up the automatic updates

* Set it up in a crontab:
```
/path/to/WebHashcat/cron.py <webhashcat_ip/host> <webhashcat_port> [--ssl]
```

#### Dependencies

- python3
- django >= 2
- hashcat >= 3
