"""Real database error output, and text that only looks like it.

WSTG-INPV-05.2 decides from the response body alone, so the thing that has to
be got right is the difference between an engine's error and a page that talks
about engines. Both sides are here, and both are served over HTTP so the case
can be driven through the real runner rather than the pattern being matched in
isolation.

The BENIGN side is not invented. `juice_shop_bundle` is the text that made the
existing INPV-05 pattern fire eleven times during the 2026-09-09 baseline: a
challenge description inside Juice Shop's own JavaScript, on a `.js` file that
is a discovered endpoint like any other.

Run: python sql_error_pages.py [port]
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# Each is the string a web application leaks, as it reaches the HTTP response.
DATABASE_ERRORS = {
    "mysql_php": '<br /><b>Fatal error</b>:  Uncaught mysqli_sql_exception: You have an error in '
                 "your SQL syntax; check the manual that corresponds to your MySQL server "
                 "version for the right syntax to use near 'probe'' at line 1 in /var/www/x.php:11",
    "mysql_legacy": "<b>Warning</b>: mysql_fetch_array() expects parameter 1 to be resource, "
                    "boolean given in /var/www/html/index.php on line 22",
    "mysql_column": "Unknown column 'erlik' in 'where clause'",
    "postgres_psycopg2": 'psycopg2.errors.SyntaxError: syntax error at or near "probe"\nLINE 1: ...',
    "postgres_rails": "PG::SyntaxError: ERROR:  unterminated quoted string at or near \"'probe\"",
    "oracle": "ORA-01756: quoted string not properly terminated",
    "mssql_odbc": "Unclosed quotation mark after the character string 'probe'.",
    "mssql_dotnet": "System.Data.SqlClient.SqlException: Incorrect syntax near 'probe'.",
    "mssql_oledb": "Microsoft OLE DB Provider for SQL Server error '80040e14'",
    "sqlite_python": "sqlite3.OperationalError: unrecognized token: \"'probe\"",
    "sqlite_ruby": "SQLite3::SQLException: unrecognized token: \"'probe\"",
    "pdo": "SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error",
    "jdbc": "java.sql.SQLException: ORA-00933: SQL command not properly ended",
    "hibernate": "org.hibernate.exception.SQLGrammarException: could not prepare statement",
}

# Pages that mention databases and are not errors. A finding on any of these is
# a HIGH-severity report delivered for a request that proved nothing.
BENIGN_PAGES = {
    "juice_shop_bundle": '{text:"Did you spot the error message with the `SQLITE_ERROR` and the '
                         'entire SQL query in the 500 response?",solved:!1}',
    "sql_tutorial": "<h1>Learn SQL</h1><p>This chapter explains SQL syntax for beginners, "
                    "including SELECT, WHERE and JOIN.</p>",
    "form_hint": '<label>Query</label><span class="hint">Check your SQL syntax before '
                 "submitting.</span>",
    "api_json": '{"sqlstate": null, "rows": 0, "error": null}',
    "hidden_input": '<input type="hidden" name="sqlstate" value="">',
    "error_reference": "<p>SQLSTATE values are five characters long. The ORA prefix is used by "
                       "Oracle for its own error codes.</p>",
    "route_listing": '{"routes": ["/api/sqlite3/status", "/api/mysql/health"]}',
    "unrelated_warning": "<b>Warning</b>:  Undefined array key \"password\" in "
                         "/var/www/html/vulnerabilities/brute/source/low.php on line 12",
    "changelog": "<li>Fixed: pg_query() calls are now parameterised (see #412)</li>",
    "changelog_mysql": "<li>Deprecated: mysql_fetch_array() is removed in 8.0; use mysqli_"
                       "fetch_assoc() instead.</li>",
    "docs_ora": "<p>See ORA-01756 in the Oracle reference for quoting rules.</p>",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        name = self.path.split("?", 1)[0].strip("/")
        body = DATABASE_ERRORS.get(name) or BENIGN_PAGES.get(name)
        if body is None:
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
