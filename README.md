# BanManager
Software for managing the sanctions of students in school computer rooms.

This software is being developed for the purpose of my NEA for my Computer Science A-Level

It is currently incomplete, and much of this README is expected to change. For example, I intend to write a client that will take advantage of the server. 

# Database Setup
Below I have written the structure of the database used. Bold fields are primary keys, emphasised fields are foreign keys.

## Students
|Field        |Datatype |Encrypted?|
|:-----------:|:-------:|:--------:|
|**Username** |VARBINARY|Yes       |
|Forename     |VARBINARY|Yes       |
|Surname      |VARBINARY|Yes       |

## Incidents
|Field         |Datatype |Encrypted?|
|:------------:|:-------:|:--------:|
|**IncidentID**|INTEGER  |No        |
|*Username*    |VARBINARY|Yes       |
|Report        |BLOB     |Yes       |
|Date          |DATE     |No        |

## Sanctions
|Field         |Datatype |Encrypted?|
|:------------:|:-------:|:--------:|
|**SanctionID**|INTEGER  |No        |
|StartDate     |DATE     |No        |
|EndDate       |DATE     |No        |
|Sanction      |BLOB     |Yes       |
|*IncidentID*  |INTEGER  |No        |

## Accounts
|Field         |Datatype      |Encrypted?|
|:------------:|:------------:|:--------:|
|**Login**     |VARCHAR       |No        |
|PasswordHash  |BINARY(32)    |No        |
|PublicKey     |TEXT          |No        |
|PrivateKey    |BLOB          |Yes       |
|AccountType   |INTEGER       |No        |
|Email         |VARBINARY(256)|Yes       |

## FileKeys
|Field         |Datatype |Encrypted?|
|:------------:|:-------:|:--------:|
|**_Login_**   |VARCHAR  |No        |
|**FileID**    |VARCHAR  |No        |
|DecryptionKey |BLOB     |Yes       |


Most fields are encrypted using the database key. However, Accounts.PrivateKey is encrypted using a key unique to that username and password combination, and FileKeys.DecryptionKey is encrypted with the user's RSA public key.

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

## /add_new_incident
Adds a new incident that pertains to a particular student. The username must have already been added with `/add_new_student`. If the date is not specified, it defaults to the current date.

*Arguments:*

* `user`: Username of the student who the incident pertains to.
* `report`: The report of the incident. This should detail what happened.
* `date` (optional): The date of the incident, in YYYY-MM-DD format.

## /add_new_sanction
Adds a new sanction in response to a particular incident. This requires a start and end date for the sanction (an "indefinite" sanction should just be a very far end date, for example 100 years). 

*Arguments:*

* `id`: ID of the incident.
* `sanction`: The sanction to be imposed.
* `start_date`: The start date of the sanction, in YYYY-MM-DD format.
* `end_date`: The end date of the sanction, in YYYY-MM-DD format.

## /query_student
Queries the database for student records. This either returns **all** student stored in the database, or can be filtered based on the optional arguments supplied in the GET parameters.

*Arguments:*

* `user` (optional): Filter based on username
* `forename` (optional): Filter based on forename
* `surname` (optional): Filter based on surname
* `like` (optional): Boolean field. If True, an SQL "LIKE" query is performed. This returns any records that contain the search strings.

*Returns:*

