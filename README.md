# BanManager
Software for managing the sanctions of students in school computer rooms.

This software is being developed for the purpose of my NEA for my Computer Science A-Level

It is currently incomplete, and much of this README is expected to change. For example, I intend to write a client that will take advantage of the server. 

# Contents
* [Database Setup](#database-setup)
    * [Students](#students)
    * [Incidents](#incidents)
    * [Sanctions](#sanctions)
    * [Accounts](#accounts)
    * [FileKeys](#filekeys)
* [API Reference](#api-reference)
    * [/init](#init)
    * [/login](#login)
    * [/query_student](#query_student)
    * [/query_incident](#query_incident)
    * [/query_sanction](#query_sanction)
    * [/add_new_student](#add_new_student)
    * [/add_new_incident](#add_new_incident)
    * [/add_new_sanction](#add_new_sanction)
    * [/modify_student](#modify_student)
    * [/modify_incident](#modify_incident)
    * [/modify_sanction](#modify_sanction)
    * [/change_password](#change_password)
    * [/add_new_account](#add_new_account)
    * [/delete_account](#delete_account)

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
|Salt          |BINARY(8)     |No
|PublicKey     |TEXT          |No        |
|PrivateKey    |BLOB          |Yes       |
|AccountType   |INTEGER       |No        |

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

*Method:* POST

*Arguments:* 

* `user`: SQL username. This can be the root username, though I recommend setting up a new user and limiting it to just your new database.
* `pass`: SQL password. 
* `host` (optional): Specifies the hostname for your database. If omitted, defaults to localhost.

*Returns:*

* `initialised` bool: If this exists, it will be `true`. Indicator of success for initialising the database.
* `password` string: The password for the new administrator account, *admin*.

## /login
Log in as a user. This requires cookies to log you in, and you must log in before you can perform most other actions.

*Method:* POST

*Arguments:*

* `user`: Site username.
* `pass`: Site password.

## /query_student
Queries the database for student records. This either returns **all** student stored in the database, or can be filtered based on the optional arguments supplied in the GET parameters.

*Method:* GET

*Arguments:*

* `user` (optional): Filter based on username
* `forename` (optional): Filter based on forename
* `surname` (optional): Filter based on surname
* `like` (optional): Boolean field. If True, an SQL "LIKE" query is performed. This returns any records that contain the search strings.

*Returns:*

This will return a list of dictionaries with the following structure.

* `Username`: Student's username.
* `Forename`: Student's forename.
* `Surname`: Student's surname.

## /query_incident
Queries the database for incidents that have been reported. Like [/query_student](#query_student), this returns all the incident, or can be filtered with the optional arguments.

*Method:* GET

*Arguments:*

* `user` (optional): Username of the student associated with the incident.
* `before` (optional): Get incidents from before this date, with the date in YYYY-MM-DD format.
* `after` (optional): Get incidents from after this date, with the date in YYYY-MM-DD format.
* `id` (optional): Get the incident with this IncidentID.

*Returns:*

This will return a list of dictionaries with the following structure.

* `ID`: IncidentID for this incident.
* `Username`: The username of the student this incident is about.
* `Report`: The report from the prefects of what the student did.
* `Date`: The date the incident occurred on, in YYYY-MM-DD format.

## /query_sanction
Queries the database for sanctions that have been submitted. Again, like [/query_student](#query_student) and [/query_incident](#query_incident), this will return all sanctions, or can be filtered with the GET parameters.

*Method:* GET

*Arguments:*

* `incident` (optional): Get the sanction with this IncidentID.
* `starts_before` (optional): Get sanctions that start before this date, with the date in YYYY-MM-DD format.
* `starts_after` (optional): Get sanctions that start after this date, with the date in YYYY-MM-DD format.
* `ends_before` (optional): Get sanctions that end before this date, with the date in YYYY-MM-DD format.
* `ends_after` (optional): Get sanctions that end after this date, with the date in YYYY-MM-DD format.
* `id` (optional): Get the sanction with this SanctionID.

*Returns:*

This will return a list of dictionaries with the following structure.

* `ID`: SanctionID for this sanction.
* `StartDate`: Date this sanction starts, in YYYY-MM-DD format.
* `EndDate`: Date this sanction ends, in YYYY-MM-DD format.
* `Sanction`: The sanction being imposed.
* `IncidentID`: The IncidentID of the incident this sanction belongs to.

## /photo
Gets the decrypted photograph of the student. Photos are stored in an encrypted form at the path specified in the config file.

*Method:* GET

*Arguments:*

* `user`: Username of the student.

## /add_new_student
Adds a new student's username to the database. The username must be unique to that student. If the forename and surname of the student are also known, that can also be added.

These fields are encrypted with a 256-bit AES key in order to conform with the Data Protection Act.

*Method:* POST

*Arguments:*

* `user`: Username of the student.
* `forename` (optional): Student's forename.
* `surname` (optional): Student's surname.

## /add_new_incident
Adds a new incident that pertains to a particular student. The username must have already been added with `/add_new_student`. If the date is not specified, it defaults to the current date.

*Method:* POST

*Arguments:*

* `user`: Username of the student who the incident pertains to.
* `report`: The report of the incident. This should detail what happened.
* `date` (optional): The date of the incident, in YYYY-MM-DD format.

*Files:*

* `photo` (optional): Photograph of the student to be uploaded. This will be encrypted.

## /add_new_sanction
Adds a new sanction in response to a particular incident. This requires a start and end date for the sanction (an "indefinite" sanction should just be a very far end date, for example 100 years). 

*Method:* POST

*Arguments:*

* `id`: ID of the incident.
* `sanction`: The sanction to be imposed.
* `start_date`: The start date of the sanction, in YYYY-MM-DD format.
* `end_date`: The end date of the sanction, in YYYY-MM-DD format.

## /modify_student
Allows you to modify a student's details. This only requires the username of the student you want to modify -- the rest of the fields are optional.

*Method:* POST

*Arguments:*

* `user`: Username of the student.
* `new_user` (optional): Username to change the student to.
* `forename` (optional): Forename to give the student.
* `surname` (optional): Surname to give the student.
* `delete_photo` (optional): Bool. Avoid specifying if you aren't using it, as any string counts as true. Deletes the student's photograph.
* `delete` (optional): Bool. Avoid specifying if you aren't using it, as any string counts as true. Deletes the student, any attached incidents, and any attached sanctions.

*Files:*

* `photo` (optional): Photograph of the student to be uploaded. This will be encrypted.

## /modify_incident
Allows you to modify the details of an incident report. This requires the incident ID.

*Method:* POST

*Arguments:*

* `id`: ID of the incident.
* `report` (optional): New report text for the incident.
* `date` (optional): New date of the incident.
* `delete` (optional): Bool. Avoid specifying if you aren't using it, as any string counts as true. Deletes the incident and any attached sanctions.

## /modify_sanction
Allows you to modify the details of a sanction. This requires the sanction ID. 

*Method:* POST

*Arguments:*

* `id`: ID of the sanction.
* `new_incident` (optional): New incident ID for the sanction.
* `sanction` (optional): New sanction to be applied to the student.
* `start_date` (optional): New start date for the sanction, in YYYY-MM-DD formmat.
* `end_date` (optional): New end date for the sanction, in YYYY-MM-DD format.
* `delete` (optional): Bool. Avoid specifying if you aren't using it, as any string counts as true. Deletes the sanction.

## /change_password
Change the current user's password, and logs the user out.

*Method:* POST

*Arguments:*

* `pass`: User's current password.
* `new`: New password for the user.

## /add_new_account
Add a new user account. This user requires a login name, password, and a rank. Ranks go from 0 to 2, with 0 being Administrator, 1 being Teacher, and 2 being Prefect. This controls the functions that the user will have access to. Additionally, users can be created with a rank lower than 2. This essentially makes the account read-only; they will be able to read data from the database, but not modify it.

*Method:* POST

*Arguments:*

* `user`: User's new username.
* `pass`: User's new password.
* `rank`: The rank of the user. 

## /delete_account
This can be used by an admin to delete another user's account (for example, to delete the prefect account at the end of a school year, or remove a teacher after they have left the school), or by a user to delete their own account. By default, users are not able to delete their own account -- to allow this, set `USERS_CAN_DELETE_THEMSELVES` in the config file to `1`. For a user to delete their own account, they must provide their password.

*Method:* POST

*Arguments:*

* `user`: User to be deleted.
* `pass`: User's password. Required if the user is deleting their own account. 