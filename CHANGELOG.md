### version 0.3.6
* Now have fully tested Oracle statement this removes the ";" that was causing OAR-0099 errors
### version 0.3.5
* Change password generator to remove punctuation due to issues with oracle and these characters. Increase default password length.
* Replace random with secrets to generate stronger cryptographicaly secure passwords.
### version 0.3.4
* Added more characters to be exclude din passwords due to limitations with Oracle
### version 0.3.3
* Changed way password statement is for Oracle is surrounded which allows more symbols
### version 0.3.2
* Made service key account rotator create SA identical to standard api 9add decoding of privatekey to the data that is stored)
### version 0.3.1
* Widened the range of versions of google-api-python-client and google-cloud-storage the module depends upon to include 1.0 and 2.0 versions not just 2.0
### version 0.3.0
* Moved tests to pytds due to unreliability of error handling in pymssql
* Added support for connection strings so can work with pydobc
* Added DBApiMasterUserPasswordRotatorConstants and DBApiMasterUserPasswordRotator so Master user rotator frameworks
* Refactored database rotators to a base class DBRotator to reduce duplicated code in SingleUser and MasterUser DB rotators
* Added tests for database master user rotator Postgres, MySQL and MSSQL
### version 0.2.3
* Added MYSQL and MSSQL support and tested password rotation for these 
* Added handling of characters in user names that look like sql injection
* Added new exception class to handle bad characters in username or initial secret
* Added to bad characters in password string to work around escaping in MySQL of \
### version 0.2.2
* Added tests for postgressdatabase password rotation
* Fixed bugs found in testing
### version 0.2.1
* Fixed bugs in rotation frameworks
* Added basis of DBApiSingleUserPasswordRotator (alpha)
### version 0.2.0
* Added secret rotator framework and tests
* Added concrete implementation of apikey rotator and service account key rotator
### version 0.1.3, 0.1.4 and 0.1.5
* Improved README
### version 0.1.2
* Corrected text in short description
### version 0.1.1
* Remove uneeded setup.py dependency
* Change mechanism to define dependnecies to remove release candidates and stick withs tble versions
### version 0.1.0
* Correct formating in preformance test
### version 0.0.9
* Add performance tests to show impact of cache performance on secret fetching at scle
### version 0.0.8
* Fix state issue when ok to start followed by exception later
* Expand tests to cover this scenario
### version 0.0.7
* Fix issue with threads not garbage collecting by using weakref
### version 0.0.6
* We now surpress server and quota issues if secret is set. So handle server based errors to make client more reliable
### version 0.0.4 and 0.0.5
* Improvements in README
### version 0.0.3
* Fix home page link
### version 0.0.2
* Add tests for decorators
* Refactor code so imports work correctly
* Bump version
### version 0.0.1
Initial release