# About dburl

Package dburl provides a standard, URL style mechanism for parsing and
opening SQL database connection strings for [Go](https://golang.org/project),
supporting standard URLs for the standard databases PostgreSQL, MySQL, SQLite3,
Oracle, Microsoft SQL Server, and most other databases with a publicly
available Go driver.

## Database URL Connection Strings

Supported database URLs are of the form:

```
   protocol+transport://user:pass@host/dbname?opt1=a&opt2=b
   protocol:/path/to/file
```

Where:

| Component          | Description                                                                          |
|--------------------|--------------------------------------------------------------------------------------|
| protocol           | driver name or alias (see below)                                                     |
| transport          | "tcp", "udp", "unix" or driver name (odbc/oleodbc)                                   |
| user               | username                                                                             |
| pass               | password                                                                             |
| host               | host                                                                                 |
| dbname<sup>*</sup> | database, instance, or service name/ID to connect to                                 |
| ?opt1=...          | additional database driver options (see respective SQL driver for available options) |

<i><sup><b>*</b></sup> for Microsoft SQL Server, the syntax to supply an
instance and database name is `/instance/dbname`, where `/instance` is
optional. For Oracle databases, `/dbname` is the unique database ID (SID).
Please see below for examples.</i>

## Quickstart

Database connection URLs (as described below) can be parsed with `Parse` as such:

```go
u, err := dburl.Parse("postgresql://user:pass@localhost/mydatabase/?sslmode=disable")
if err != nil { /* ... */ }
```

Additionally, a simple helper func `Open`, is available to quickly parse, open,
and return a standard SQL database connection:

```go
db, err := dburl.Open("sqlite:mydatabase.sqlite3?loc=auto")
if err != nil { /* ... */ }
```

## Example URLs ##

 The following are URLs that can be handled with a call to `Open` or `Parse`:

```
   postgres://user:pass@localhost/dbname
   pg://user:pass@localhost/dbname?sslmode=disable
   mysql://user:pass@localhost/dbname
   mysql:/var/run/mysqld/mysqld.sock
   sqlserver://user:pass@remote-host.com/dbname
   mssql://user:pass@remote-host.com/instance/dbname
   ms://user:pass@remote-host.com:port/instance/dbname?keepAlive=10
   oracle://user:pass@somehost.com/oracledb
   sap://user:pass@localhost/dbname
   sqlite:/path/to/file.db
   file:myfile.sqlite3?loc=auto
   odbc+postgres://user:pass@localhost:port/dbname?option1=
```

## Protocol Schemes and Aliases

The following protocols schemes (ie, driver) and their associated aliases are
supported out of the box:

| Database (scheme/driver)     | Protocol Aliases [real driver]        |
|------------------------------|---------------------------------------|
| Microsoft SQL Server (mssql) | ms, sqlserver                         |
| MySQL (mysql)                | my, mariadb, maria, percona, aurora   |
| Oracle (ora)                 | or, oracle, oci8, oci                 |
| PostgreSQL (postgres)        | pg, postgresql, pgsql                 |
| SQLite3 (sqlite3)            | sq, sqlite, file                      |
|                              |                                       |
| Amazon Redshift (redshift)   | rs [postgres]                         |
| CockroachDB (cockroachdb)    | cr, cockroach, crdb, cdb [postgres]   |
| MemSQL (memsql)              | me [mysql]                            |
| TiDB (tidb)                  | ti [mysql]                            |
| Vitess (vitess)              | vt [mysql]                            |
|                              |                                       |
| Google Spanner (spanner)     | gs, google, span (not yet public)     |
|                              |                                       |
| MySQL (mymysql)              | zm, mymy                              |
| PostgreSQL (pgx)             | px                                    |
|                              |                                       |
| Apache Avatica (avatica)     | av, phoenix                           |
| Apache Ignite (ignite)       | ig, gridgain                          |
| Cassandra (cql)              | ca, cassandra, datastax, scy, scylla  |
| ClickHouse (clickhouse)      | ch                                    |
| Couchbase (n1ql)             | n1, couchbase                         |
| Cznic QL (ql)                | ql, cznic, cznicql                    |
| Firebird SQL (firebirdsql)   | fb, firebird                          |
| Microsoft ADODB (adodb)      | ad, ado                               |
| ODBC (odbc)                  | od                                    |
| OLE ODBC (oleodbc)           | oo, ole, oleodbc [adodb]              |
| Presto (presto)              | pr, prestodb, prestos, prs, prestodbs |
| SAP HANA (hdb)               | sa, saphana, sap, hana                |
| Snowflake (snowflake)        | sf                                    |
| VoltDB (voltdb)              | vo, volt, vdb                         |

Any protocol scheme `alias://` can be used in place of `protocol://`, and will work
identically with `Parse`/`Open`.

## Installation

Install in the usual Go fashion:

```sh
go get -u github.com/xo/dburl
```

## Usage

Please note that the dburl package does not import actual SQL drivers, and only
provides a standard way to parse/open respective database connection URLs.

For reference, these are the following "expected" SQL drivers that would need
to be imported:

| Database (driver)            | Package                                                                                     |
|------------------------------|---------------------------------------------------------------------------------------------|
| Microsoft SQL Server (mssql) | [github.com/denisenkom/go-mssqldb](https://github.com/denisenkom/go-mssqldb)                |
| MySQL (mysql)                | [github.com/go-sql-driver/mysql](https://github.com/go-sql-driver/mysql)                    |
| Oracle (ora)                 | [gopkg.in/rana/ora.v4](https://gopkg.in/rana/ora.v4)                                        |
| PostgreSQL (postgres)        | [github.com/lib/pq](https://github.com/lib/pq)                                              |
| SQLite3 (sqlite3)            | [github.com/mattn/go-sqlite3](https://github.com/mattn/go-sqlite3)                          |
|                              |                                                                                             |
| Amazon Redshift (redshift)   | [github.com/lib/pq](https://github.com/lib/pq)                                              |
| CockroachDB (cockroachdb)    | [github.com/lib/pq](https://github.com/lib/pq)                                              |
| MemSQL (memsql)              | [github.com/go-sql-driver/mysql](https://github.com/go-sql-driver/mysql)                    |
| TiDB (tidb)                  | [github.com/go-sql-driver/mysql](https://github.com/go-sql-driver/mysql)                    |
| Vitess (vitess)              | [github.com/go-sql-driver/mysql](https://github.com/go-sql-driver/mysql)                    |
|                              |                                                                                             |
| Google Spanner (spanner)     | github.com/xo/spanner (not yet public)                                                      |
|                              |                                                                                             |
| MySQL (mymysql)              | [github.com/ziutek/mymysql/godrv](https://github.com/ziutek/mymysql)                        |
| PostgreSQL (pgx)             | [github.com/jackc/pgx/stdlib](https://github.com/jackc/pgx)                                 |
|                              |                                                                                             |
| Apache Avatica (avatica)     | [github.com/Boostport/avatica](https://github.com/Boostport/avatica)                        |
| Apache Ignite (ignite)       | [github.com/amsokol/ignite-go-client/sql](https://github.com/amsokol/ignite-go-client)      |
| Cassandra (cql)              | [github.com/MichaelS11/go-cql-driver](https://github.com/MichaelS11/go-cql-driver)          |
| ClickHouse (clickhouse)      | [github.com/kshvakov/clickhouse](https://github.com/kshvakov/clickhouse)                    |
| Couchbase (n1ql)             | [github.com/couchbase/go_n1ql](https://github.com/couchbase/go_n1ql)                        |
| Cznic QL (ql)                | [github.com/cznic/ql](https://github.com/cznic/ql)                                          |
| Firebird SQL (firebirdsql)   | [github.com/nakagami/firebirdsql](https://github.com/nakagami/firebirdsql)                  |
| Microsoft ADODB (adodb)      | [github.com/mattn/go-adodb](https://github.com/mattn/go-adodb)                              |
| ODBC (odbc)                  | [github.com/alexbrainman/odbc](https://github.com/alexbrainman/odbc)                        |
| OLE ODBC (oleodbc)           | [github.com/mattn/go-adodb](https://github.com/mattn/go-adodb)                              |
| Presto (presto)              | [github.com/prestodb/presto-go-client/presto](https://github.com/prestodb/presto-go-client) |
| SAP HANA (hdb)               | [github.com/SAP/go-hdb/driver](https://github.com/SAP/go-hdb)                               |
| Snowflake (snowflake)        | [github.com/snowflakedb/gosnowflake](https://github.com/snowflakedb/gosnowflake)            |
| VoltDB (voltdb)              | [github.com/VoltDB/voltdb-client-go/voltdbclient](github.com/VoltDB/voltdb-client-go])      |

Please see [the GoDoc API page](http://godoc.org/github.com/xo/dburl) for a
full API listing.

### URL Parsing Rules

`Parse` and `Open` rely heavily on the standard `net/url.URL` type, as such
parsing rules have the same conventions/semantics as any URL parsed by the
standard library's `net/url.Parse`.

## Full Example

A full example for reference:

```go
// example/example.go
package main

import (
    "fmt"
    "log"

    _ "github.com/denisenkom/go-mssqldb"
    "github.com/xo/dburl"
)

func main() {
    db, err := dburl.Open("sqlserver://user:pass@localhost/dbname")
    if err != nil {
        log.Fatal(err)
    }

    var name string
    err = db.QueryRow(`SELECT name FROM mytable WHERE id=10`).Scan(&name)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf(">> got: %s\n", name)
}
```

## Related Projects

The dburl package was built primarily to support these projects:

* [usql](https://github.com/xo/usql) - a universal command-line interface for SQL databases
* [xo](https://github.com/xo/xo) - a command-line tool to generate Go code from a database schema
