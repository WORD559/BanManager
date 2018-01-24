# BanManager
Software for managing the sanctions of students in school computer rooms.

This software is being developed for the purpose of my NEA for my Computer Science A-Level

It is currently incomplete, and much of this README is expected to change. For example, I intend to write a client that will take advantage of the server. 

# API Reference

## /init
Creates a new database with the properties specified in `config/defaults.cnf`. The database will be created with an administrative user `admin` with a random password provided in the response. The server RSA key and database AES keys will also be created.

Cannot be run twice. In order to run it a second time, you must delete `config/SQLusers.cnf`, `config/key.rsa`, and drop the database from your SQL server.

*Arguments:* 

* `user`: SQL username. This can be the root username, though I recommend setting up a new user and limiting it to just your new database.
* `pass`: SQL password. 
* `host` (optional): Specifies the hostname for your database. If omitted, defaults to localhost.

*Returns:*

* `initialised` bool: If this exists, it will be `true`. Indicator of success for initialising the database.
* `password` string: The password for the new administrator account, *admin*.

## /login
Log in as a user. This requires cookies to log you in, and you must log in before you can perform most other actions.

*Arguments:*

* `user`: Site username.
* `pass`: Site password.

## /add_new_student
Adds a new student's username to the database. The username must be unique to that student. If the forename and surname of the student are also known, that can also be added.

These fields are encrypted with a 256-bit AES key in order to conform with the Data Protection Act.

*Arguments:*

* `user`: Username of the student.
* `forename` (optional): Student's forename.
* `surname` (optional): Student's surname.