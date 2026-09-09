"""An application that leaks its database errors, and applications that do not.

WSTG-INPV-05.2 now decides from a DIFFERENTIAL — a benign request first, then
the payload — so a fixture that serves the same body whatever it is asked
cannot exercise it. Every route here answers a benign value with an ordinary
page and only breaks when the value carries a quote or a paren, which is what a
concatenating application does.

Three kinds of route, and the last two are the point:

    the engine names      leak that engine's real error, but only under payload
    /always_broken        leaks the SAME real error for every request
    /numeric_sink         leaks a DIFFERENT real error for every request
    the benign names      never leak, whatever they are asked

The last two are the pair the case has to tell apart, and telling them apart is
the whole reason the payload steps compare against a baseline instead of just
matching a pattern.

`/always_broken` answers both requests identically: a debug page left on, a docs
page, an error-code table. Its error is real and the payload did not cause it,
so it is not evidence about the payload and must not be reported.

`/numeric_sink` is an unquoted numeric sink — `WHERE id = <raw>` — which errors
on every non-numeric value, so the benign probe ALREADY carries a signature.
It is also the most exploitable shape there is, needing no quote to escape.
Reproduced against real MySQL 8.0: benign gives 1054 `Unknown column`, the
payload gives 1064 `You have an error in your SQL syntax`, and `1 OR 1=1`
returns every row. A check that asked only whether a signature was present at
baseline would drop this parameter silently, and would not even hand it to
sqlmap.

The wider corpus — 66 real error bodies and 113 benign ones, most of which exist
because they broke a specific alternative — is in sql_error_corpus.py and is
matched in-process rather than served, because 179 four-request runs is a slow
way to test a regex.

Run: python sql_error_pages.py [port]
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from fixtures.sql_error_corpus import PATTERN_CANNOT_SEPARATE

# What a web application leaks, as it reaches the HTTP response. One per
# engine/driver combination the pattern claims to cover.
DATABASE_ERRORS = {
    "mysql_php": '<br /><b>Fatal error</b>:  Uncaught mysqli_sql_exception: You have an error in '
                 "your SQL syntax; check the manual that corresponds to your MySQL server "
                 "version for the right syntax to use near ''probe'' at line 1 in /var/www/x.php:11",
    "mariadb": "You have an error in your SQL syntax; check the manual that corresponds to your "
               "MariaDB server version for the right syntax to use near ''probe'' at line 1",
    "mysql_legacy": "<b>Warning</b>: mysql_fetch_array() expects parameter 1 to be resource, "
                    "boolean given in /var/www/html/index.php on line 22",
    "mysql_column": "Unknown column 'erlik' in 'where clause'",
    "postgres_libpq": 'ERROR:  unterminated quoted string at or near "\'probe"',
    "postgres_psycopg2": 'psycopg2.errors.SyntaxError: syntax error at or near "probe"\nLINE 1: ...',
    "postgres_asyncpg": "asyncpg.exceptions.PostgresSyntaxError: unterminated quoted string at "
                        'or near "\'probe"',
    "oracle": "ORA-01756: quoted string not properly terminated",
    "oracle_thin": "oracledb.exceptions.ProgrammingError: DPY-2041: missing ending quote (')",
    "mssql_odbc": "[Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Unclosed quotation mark "
                  "after the character string 'probe'.",
    "mssql_dotnet": "System.Data.SqlClient.SqlException: Incorrect syntax near 'probe''.",
    "mssql_oledb": "Microsoft OLE DB Provider for SQL Server error '80040e14'",
    "sqlite_python": "sqlite3.OperationalError: unrecognized token: \"'probe\"",
    "sqlite_ruby": "SQLite3::SQLException: unrecognized token: \"'probe\"",
    "sqlite_cli": 'Error: in prepare, near "\'probe": syntax error',
    "pdo": "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your "
           "SQL syntax; check the manual that corresponds to your MySQL server version for the "
           "right syntax to use near ''probe'' at line 1",
    "jdbc": "java.sql.SQLSyntaxErrorException: ORA-00933: SQL command not properly ended",
    # Juice Shop's own answer, captured live from the lab: SQLite accepts
    # `'erlik'` as a complete string and stops at the next identifier, so a lone
    # quote gives a PARSER row rather than `unrecognized token`. The case
    # reported nothing for this — a genuine, reachable, HTTP 500 injection on a
    # target sitting in the lab — until the parser alternative was added.
    "sqlite_parser_html": "<title>Error: SQLITE_ERROR: near &quot;probe&quot;: syntax error</title>",
    # PostgREST v14.14 over PostgreSQL 16, captured live. No `ERROR:  ` prefix
    # survives JSON encoding, so the SQLSTATE carries the message instead.
    "postgres_json": '{"code":"42601","details":null,"hint":null,'
                     '"message":"syntax error at or near \\"probe\\""}',
    # The same MySQL error as a framework renders it. htmlspecialchars turns
    # every quote into an entity, which is why no branch may require a literal
    # delimiter byte.
    "mysql_html_escaped": "<p>Query failed: You have an error in your SQL syntax; check the manual "
                          "that corresponds to your MySQL server version for the right syntax to "
                          "use near &#039;probe&#039;&#039; at line 1</p>",
    # ...and as MySQL returns it when the query spans lines, which every query
    # builder and heredoc does: the near-snippet carries the newlines with it.
    "mysql_multiline": "You have an error in your SQL syntax; check the manual that corresponds to "
                       "your MySQL server version for the right syntax to use near 'probe'\n"
                       "  AND id > 0\nORDER BY id' at line 2",
}

# Real database errors this detector deliberately CANNOT claim, kept as fixtures
# so the blind spot is a test rather than a sentence in a comment. Each is a
# wrapper class name carrying no engine text, and each is byte-identical to a
# line in an issue tracker, a Javadoc page or an OpenAPI error enum. Measured:
# every alternative that would catch these cost between one and six false
# positives and bought at most two of them.
UNREACHABLE_ERRORS = {
    "hibernate": "org.hibernate.exception.SQLGrammarException: could not prepare statement",
    "spring": "org.springframework.jdbc.BadSqlGrammarException: StatementCallback; bad SQL "
              "grammar [SELECT * FROM users WHERE name = 'probe']",
    "dotnet_sqlite": "System.Data.SQLite.SQLiteException",
}

# A page that carries a database error identically whatever it is asked — a
# debug page left on, a docs page, an error-code table. The error is real and
# the payload did not cause it, so it is not evidence about the payload.
ALWAYS_BROKEN = ("ERROR:  relation \"users\" does not exist\n"
                 "psycopg2.errors.SyntaxError: syntax error at or near \"FROM\"")

# ...and the shape that must NOT be confused with it. An unquoted numeric sink
# (`WHERE id = <raw>`) errors on EVERY non-numeric value, so the benign probe
# already carries a signature — and the parameter is nonetheless the most
# exploitable kind there is. Reproduced against real MySQL 8.0: benign gives
# 1054, the payload gives 1064, and `1 OR 1=1` returns every row. Anything that
# suppressed on the mere presence of a signature would drop this silently.
NUMERIC_SINK = {
    "benign": "Unknown column 'erlikprobebaseline' in 'where clause'",
    "provoked": "You have an error in your SQL syntax; check the manual that corresponds to "
                "your MySQL server version for the right syntax to use near ''probe'' at line 1",
}

# Pages that mention databases and are not findings. A representative subset —
# the full 113 are in sql_error_corpus.py.
BENIGN_PAGES = {
    "juice_shop_bundle": '{text:"Did you spot the error message with the `SQLITE_ERROR` and the '
                         'entire SQL query in the 500 response?",solved:!1}',
    "sql_tutorial": "<h1>Learn SQL</h1><p>This chapter explains SQL syntax for beginners, "
                    "including SELECT, WHERE and JOIN.</p>",
    "mysql_manual": "You have an error in your SQL syntax; check the manual that corresponds to "
                    "your MySQL server version for the right syntax to use near '%s' at line 1",
    "mssql_error_table": "<tr><td>105</td><td>15</td><td>Unclosed quotation mark after the "
                         "character string '%.*ls'.</td></tr>",
    "waf_block": '{"blocked":true,"rule_id":"942100","signature":"Unclosed quotation mark after '
                 'the character string \'"}',
    "search_dsl_echo": '{"error":{"type":"query_parse_error","reason":"unrecognized token: '
                       '\\"\'\\" at position 12"}}',
    "parameterized_pg": 'ERROR:  invalid input syntax for type integer: "1\'"\n'
                        "CONTEXT:  unnamed portal parameter $1 = '...'",
    "openapi_enum": '{"components":{"schemas":{"DbError":{"properties":{"exception":{"enum":'
                    '["PDOException","java.sql.SQLException","SequelizeDatabaseError"]}}}}}}',
    "issue_tracker": '{"issues":[{"title":"SQLGrammarException: could not extract ResultSet",'
                     '"count":5},{"title":"OperationalError at /api/v1/orders","count":412}]}',
    "ora_ticket_key": "<li>ORA-01756 &mdash; reduced cold-start latency on the orders service</li>",
    "ora_route_listing": "GET /api/v1/db/errors/ora-01756",
    "lowercased_log": "you have an error in your sql syntax; check the manual that corresponds "
                      "to your mysql server version for the right syntax to use near 'x' at line 1",
    "hidden_input": '<input type="hidden" name="sqlstate" value="">',
    "changelog": "<li>Fixed: pg_query() calls are now parameterised (see #412)</li>",
    "unrelated_warning": "<b>Warning</b>:  Undefined array key \"pg_num\" in "
                         "/var/www/html/list.php on line 12",
}

BREAKS_ON = ("'", '"', ")")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        name = parts.path.strip("/")
        value = (parse_qs(parts.query).get("id") or [""])[0]
        provoked = any(c in value for c in BREAKS_ON)

        if name in DATABASE_ERRORS or name in UNREACHABLE_ERRORS:
            leak = DATABASE_ERRORS.get(name) or UNREACHABLE_ERRORS[name]
            body = leak if provoked else f"<p>No user matching {len(value)} characters.</p>"
        elif name == "always_broken":
            body = ALWAYS_BROKEN
        elif name == "numeric_sink":
            body = NUMERIC_SINK["provoked" if provoked else "benign"]
        elif name in BENIGN_PAGES:
            body = BENIGN_PAGES[name]
        elif name in PATTERN_CANNOT_SEPARATE:
            # The pattern matches these. Only the comparison drops them, which
            # is the point of serving them identically to every request.
            body = PATTERN_CANNOT_SEPARATE[name]
        else:
            self.send_response(404)
            self.end_headers()
            return

        payload = f"<html><body>{body}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 9093),
               Handler).serve_forever()
