"""The corpus this detector is measured against, and where every body came from.

WSTG-INPV-05.2 decides from a response body alone, so the only thing that says
whether its pattern is any good is a corpus of bodies. This is that corpus.

POSITIVE_BODIES are real database errors, across 31 engine/driver/ORM
combinations. Most were produced live against running engines — MySQL 8.0,
MariaDB 10.11, PostgreSQL 16, SQLite and the drivers and ORMs above them; the
rest come from vendor documentation and sqlmap's own errors.xml.

BENIGN_BODIES are pages that are NOT findings, and they are the half that
matters. The first version of this fixture had eleven of them, all easy, and the
pattern it certified went on to score 31 false positives against this set —
six of them from `java.sql.SQLException` alone, which bought zero real errors.

Most bodies here exist because they broke a specific alternative:

    a Javadoc page, an `import` line, a `rescue` clause, an OpenAPI error enum
    and an issue-tracker title      -> a class name is not an error
    `Aurora-2024`, an ORA-prefixed ticket key, and
    `Invalid parameter ORA-00933: expected integer`
                                    -> an error code must carry its message
    MySQL's own manual (`near '%s' at line 1`) and Microsoft's error table
    (`'%.*ls'`)                     -> documentation carries the message too
    a search DSL and a CSP report endpoint answering a lone quote with
    `unrecognized token: "\'"`      -> the target can echo the payload back
    a correctly parameterized PostgreSQL app answering `1'` with
    `invalid input syntax for type integer`
                                    -> a CORRECT application can look like a
                                       finding, and a differential CONFIRMS it

Adding a body here is how a false positive is stopped from coming back.
"""

POSITIVE_BODIES = {
    'live_php85_mysqli_report_error': "<br />\n<b>Warning</b>:  mysqli::query(): (42000/1064): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'probe'' at line 1 in <b>Command line code</b> on line <b>4</b><br />",
    'live_mysql_1064_html_escaped': '<p>Query failed: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near &#039;probe&#039;&#039; at line 1</p>',
    'live_mysql_1064_multiline': "ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'probe'\n  AND id > 0\nORDER BY id' at line 2",
    'live_postgrest_json_42601': '{"code":"42601","details":null,"hint":null,"message":"syntax error at or near \\"probe\\""}',
    'live_juice_shop_sqlite_500': '<title>Error: SQLITE_ERROR: near &quot;probe&quot;: syntax error</title>\n<h2><em>500</em> Error: SQLITE_ERROR: near &quot;probe&quot;: syntax error</h2>',
    'fixture_hibernate': 'org.hibernate.exception.SQLGrammarException: could not prepare statement',
    'fixture_jdbc': 'java.sql.SQLException: ORA-00933: SQL command not properly ended',
    'fixture_mssql_dotnet': "System.Data.SqlClient.SqlException: Incorrect syntax near 'probe'.",
    'fixture_mssql_odbc': "Unclosed quotation mark after the character string 'probe'.",
    'fixture_mysql_column': "Unknown column 'erlik' in 'where clause'",
    'fixture_mysql_legacy': '<b>Warning</b>: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/index.php on line 22',
    'fixture_mysql_php': "<br /><b>Fatal error</b>:  Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'probe'' at line 1 in /var/www/x.php:11",
    'fixture_oracle': 'ORA-01756: quoted string not properly terminated',
    'fixture_pdo': 'SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error',
    'fixture_postgres_psycopg2': 'psycopg2.errors.SyntaxError: syntax error at or near "probe"\nLINE 1: ...',
    'fixture_postgres_rails': 'PG::SyntaxError: ERROR:  unterminated quoted string at or near "\'probe"',
    'fixture_sqlite_python': 'sqlite3.OperationalError: unrecognized token: "\'probe"',
    'fixture_sqlite_ruby': 'SQLite3::SQLException: unrecognized token: "\'probe"',
    'synthesis_must_match': "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1",
    'synthesis_must_match_10': "Unclosed quotation mark after the character string ''.",
    'synthesis_must_match_11': 'java.sql.SQLSyntaxErrorException: ORA-01756: quoted string not properly terminated',
    'synthesis_must_match_2': "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''' at line 1",
    'synthesis_must_match_3': 'ERROR:  unterminated quoted string at or near "\'"',
    'synthesis_must_match_4': 'ERROR:  syntax error at or near "1"',
    'synthesis_must_match_5': 'psycopg2.errors.SyntaxError: unterminated quoted string at or near "\'"',
    'synthesis_must_match_6': 'Exception Value: unrecognized token: &quot;&#x27;apple&#x27;&#x27;&quot;',
    'synthesis_must_match_7': '<h2>SQLite3::SQLException: unrecognized token: &quot;&#39;apple&#39;&#39;)&quot;:</h2>',
    'synthesis_must_match_8': "[Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Unclosed quotation mark after the character string 'apple''.",
    'synthesis_must_match_9': "Microsoft OLE DB Provider for SQL Server error '80040e14'",
    'workflow_django_orm_django_db_any': 'Exception Type: OperationalError at /u\nException Value: unrecognized token: &quot;&#x27;apple&#x27;&#x27;&quot;',
    'workflow_doctrine_dbal_php_engine': "An exception occurred while executing a query: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''apple''' at line 1",
    'workflow_hibernate_5_jpa': 'javax.persistence.PersistenceException: org.hibernate.exception.SQLGrammarException: could not extract ResultSet',
    'workflow_hibernate_6_jpa_driver_th': 'org.hibernate.exception.GenericJDBCException: could not prepare statement [[SQLITE_ERROR] SQL error or missing database (unrecognized token: "\'apple\'\'")] [SELECT * FROM users WHERE name = \'apple\'\']',
    'workflow_hibernate_6_jpa_engine_na': "org.hibernate.exception.SQLGrammarException: JDBC exception executing SQL [SELECT * FROM users WHERE user = 'apple''] [You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''apple''' at line 1] [n/a]",
    'workflow_microsoft_sql_server': 'pyodbc.ProgrammingError: (\'42000\', "[42000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Unclosed quotation mark after the character string \'apple\'\'. (105) (SQLExecDirectW)")',
    'workflow_microsoft_sql_server_2': "Microsoft.Data.SqlClient.SqlException (0x80131904): Unclosed quotation mark after the character string 'apple''.\nIncorrect syntax near 'apple''.\n   at Microsoft.Data.SqlClient.SqlConnection.OnError(SqlException exception, Boolean breakConnection, Action`1 wrapCloseInAction)\n   ...\nClientConnectionId:567aeb53-692d-4b8f-8071-8db861242893\nError Number:105,State:1,Class:15",
    'workflow_microsoft_sql_server_3': "com.microsoft.sqlserver.jdbc.SQLServerException: Unclosed quotation mark after the character string 'apple''.",
    'workflow_microsoft_sql_server_4': "Unclosed quotation mark after the character string 'apple''.",
    'workflow_microsoft_sql_server_5': "Microsoft OLE DB Provider for SQL Server error '80040e14'\nUnclosed quotation mark after the character string ''.",
    'workflow_microsoft_sql_server_6': "Incorrect syntax near 'apple''.",
    'workflow_mysql_8_0_45': "<b>Fatal error</b>:  Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1 in /var/www/html/vulnerabilities/sqli/source/low.php:11",
    'workflow_mysql_8_0_45_2': "<b>Fatal error</b>:  Uncaught PDOException: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1 in /tmp/php3.php:4",
    'workflow_mysql_8_0_45_3': 'warning form: <b>Warning</b>:  PDO::query(): SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; ... in <b>/tmp/php_probe.php</b> on line <b>12</b><br />',
    'workflow_mysql_8_0_45_mariadb_10_11': "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1",
    'workflow_mysql_8_0_45_mariadb_10_11_2': "MariaDB: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''' at line 1",
    'workflow_mysql_mariadb': 'com.mysql.cj.jdbc.exceptions.MySQLSyntaxErrorException: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ...',
    'workflow_oracle': 'java.sql.SQLSyntaxErrorException: ORA-01756: quoted string not properly terminated\n\nhttps://docs.oracle.com/error-help/db/ora-01756/',
    'workflow_oracle_2': "oracledb.exceptions.ProgrammingError: DPY-2041: missing ending quote (')",
    'workflow_oracle_3': '<br />\n<b>Warning</b>:  oci_execute(): ORA-01756: quoted string not properly terminated in <b>/var/www/html/q.php</b> on line <b>12</b><br />',
    'workflow_oracle_4': 'Oracle.ManagedDataAccess.Client.OracleException (0x80004005): ORA-01756: quoted string not properly terminated',
    'workflow_pdo_php_the_sqlstate_laye': "<b>Fatal error</b>:  Uncaught PDOException: SQLSTATE[HY000]: General error: 1 unrecognized token: &quot;'apple''&quot; in /tmp/pdo.php:21",
    'workflow_plain_jdbc_jdk_standard_hie': "java.sql.SQLSyntaxErrorException: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''apple''' at line 1",
    'workflow_postgresql': '<b>Warning</b>:  pg_query(): Query failed: ERROR:  unterminated quoted string at or near "\'" in <b>/var/www/html/item.php</b> on line <b>14</b><br />',
    'workflow_postgresql_16_14': 'ERROR:  unterminated quoted string at or near "\'"\nLINE 1: SELECT 1 WHERE 1 = 1\'\n                            ^',
    'workflow_postgresql_16_14_2': 'psycopg2.errors.SyntaxError: unterminated quoted string at or near "\'"\nLINE 1: SELECT * FROM items WHERE name = \'x\'\'\n                                         ^',
    'workflow_postgresql_16_14_3': 'psycopg3: psycopg.errors.SyntaxError: unterminated quoted string at or near "\'"',
    'workflow_postgresql_16_14_4': 'asyncpg.exceptions.PostgresSyntaxError: unterminated quoted string at or near "\'"',
    'workflow_postgresql_2': '<b>Fatal error</b>:  Uncaught PDOException: SQLSTATE[42601]: Syntax error: 7 ERROR:  syntax error at or near "1" in /var/www/html/q.php:9',
    'workflow_postgresql_3': 'org.postgresql.util.PSQLException: ERROR: unterminated quoted string at or near "\'"\n  Position: 39\n\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2725)',
    'workflow_rails_activerecord_adapte': 'ActiveRecord::StatementInvalid (SQLite3::SQLException: unrecognized token: "\'apple\'\')":\nSELECT "users".* FROM "users" WHERE (name = \'apple\'\')',
    'workflow_sequelize_node_behind_expr': '<pre>Error<br> &nbsp; &nbsp;at Database.&lt;anonymous&gt; (/app/node_modules/sequelize/lib/dialects/sqlite/query.js:185:27)<br> &nbsp; &nbsp;at Query.run (/app/node_modules/sequelize/lib/dialects/sqlite/query.js:183:12)</pre>',
    'workflow_sequelize_node_engine_agn': '{"error":"SQLITE_ERROR: unrecognized token: \\"\'apple\'\'\\"","name":"SequelizeDatabaseError"}',
    'workflow_spring_jdbc_spring_data_e': "org.springframework.jdbc.BadSqlGrammarException: StatementCallback; bad SQL grammar [SELECT * FROM users WHERE user = 'apple'']",
    'workflow_sqlalchemy_any_dbapi_undern': '(sqlite3.OperationalError) unrecognized token: "\'apple\'\'"\n[SQL: SELECT * FROM users WHERE name = \'apple\'\']\n(Background on this error at: https://sqlalche.me/e/20/e3q8)',
    'workflow_sqlite': 'unrecognized token: "\'apple\'\'"',
    'workflow_sqlite_2': 'Error: in prepare, near "\'x\'": syntax error',
    'workflow_sqlite_3': 'sqlite3.OperationalError: unrecognized token: "\'apple\'\'"',
    'workflow_sqlite_4': 'SQLite3::SQLException: unrecognized token: "\'apple\'\'"',
    'workflow_sqlite_5': 'org.sqlite.SQLiteException: [SQLITE_ERROR] SQL error or missing database (unrecognized token: "\'apple\'\'")',
    'workflow_sqlite_6': '{"code":"ERR_SQLITE_ERROR","errcode":1,"errstr":"SQL logic error","message":"unrecognized token: \\"\'apple\'\'\\""}',
    'workflow_sqlite_7': 'System.Data.SQLite.SQLiteException',
}

BENIGN_BODIES = {
    'correct_app_pdo_duplicate_key': "SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'a@b.c' for key 'email'",
    'correct_app_sqlite_unique_constraint': '{"error":"sqlite3.IntegrityError: UNIQUE constraint failed: users.email"}',
    'oracle_conversion_correct_app': "ORA-01722: unable to convert string value containing 'e' to a number",
    'mssql_conversion_failed_correct_app': "Conversion failed when converting the varchar value 'erlikprobe' to data type int.",
    'php8_undefined_key_named_like_a_driver': '<b>Warning</b>:  Undefined array key "mysql_id" in <b>/var/www/html/list.php</b> on line <b>9</b><br />',
    'correct_app_asyncpg_clientside': 'asyncpg.exceptions.DataError: invalid input for query argument $1: "1\'" (\'str\' object cannot be interpreted as an integer)',
    'correct_app_psycopg2_base_class': '<h1>psycopg2.DataError</h1><p>invalid input syntax for type integer: "1\'"</p>',
    'correct_app_psycopg3_type_cast': 'psycopg.errors.InvalidTextRepresentation: invalid input syntax for type integer: "1\'"',
    'live_juice_shop_benign_search': '{"status":"success","data":[]}',
    'attack_a_404_handler_that_lists_the_routes_i': '{"status": 404, "known_routes": ["GET /api/v1/db/errors/ora-01756", "POST /internal/pdo-exception-replay", "GET /debug/sqlstate"]}',
    'attack_a_bug_report_form_that_carries_the_ap': '<form method="post" action="/report">\n<input type="hidden" name="sqlstate" id="sqlstate" value="">\n<input type="hidden" name="last_error_code" value="SQLSTATE[HY000]">\n<input type="hidden" name="driver" value="System.Data.SqlClient">\n</form>',
    'attack_a_bug_report_form_that_carries_the_ap_2': 'and separately, an OpenAPI document: "exception":{"type":"string","enum":["PDOException","java.sql.SQLException","Microsoft.Data.SqlClient.SqlException", ...]}',
    'attack_a_changelog_release_notes_page_or_iss': '<li>ORA-10428 &mdash; CSV export dropped the last row on Safari</li>\n<li>ORA-10431 &mdash; reduced cold-start latency on the orders service</li>\n<li>ORA-00933 &mdash; the "remember me" checkbox was not persisted</li>',
    'attack_a_csp_report_uri_endpoint_that_echoes': '{"csp-report": {"document-uri": "https://app.example.com/search?q=%27", "violated-directive": "script-src", "blocked-uri": "https://app.example.com/vendor/sequelize/lib/dialects/postgres/query.js:185:27", "script-sample": "unrecognized token: \\"\'\\""}}',
    'attack_a_csp_report_uri_endpoint_that_echoes_2': '{"accepted":1,"event":{"stack":"Error\\n    at Query.run (/app/node_modules/sequelize/lib/dialects/postgres/query.js:185:27)"}}',
    'attack_a_deploy_render_log_shown_in_a_ci_or_': '<pre>ERROR: syntax error: "unexpected } at line 14 of values.yaml"\nERROR: syntax error: "duplicate key \'image\'"\nRender aborted after 2 errors.</pre>',
    'attack_a_django_debug_page_for_a_database_ou': '<title>OperationalError at /orders/</title>\n<h1>OperationalError at /orders/</h1>\n<pre class="exception_value">connection to server at "db" (10.0.3.2), port 5432 failed: Connection refused</pre>\n<th>Request URL:</th><td>http://app.example.com/orders/?id=1%27</td>',
    'attack_a_health_status_json_carrying_the_las': '{"db": "unhealthy", "last_error": "[Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Login failed for user \'app\'. (18456) (SQLDriverConnect)"}',
    'attack_a_hibernate_5_to_6_migration_guide_th': 'Message templates changed. Where 5.x produced <code>could not extract ResultSet</code>, 6.x produces a template that embeds the statement:\n<pre>JDBC exception executing SQL [select * from Book b where b.isbn = ?] [n/a]</pre>',
    'attack_a_javadoc_class_page_javadoc_puts_the': '<h2 title="Class MySQLSyntaxErrorException">Class com.mysql.cj.jdbc.exceptions.MySQLSyntaxErrorException</h2>',
    'attack_a_laravel_symfony_troubleshooting_blo': '<h1>Fixing SQLSTATE[HY000] [2002] Connection refused in Laravel Sail</h1>\n<p>Nine times out of ten this is DB_HOST. Inside the container the database is reachable at the service name, not at 127.0.0.1.</p>',
    'attack_a_learn_microsoft_com_handle_connecti': '<pre>catch (Microsoft.Data.SqlClient.SqlException ex) when (ex.Number == 4060)\n{\n    logger.LogWarning("database is not available for this login");\n}</pre>',
    'attack_a_log_alerting_rule_configuration_pag': '<tr><td>Storage errors</td><td>contains [SQLITE_ERROR] or [SQLITE_BUSY]</td><td>#oncall</td></tr>',
    'attack_a_php_app_that_does_the_right_thing_p': '<br />\n<b>Warning</b>:  pg_query_params(): Query failed: ERROR:  invalid input syntax for type integer: "1\'" in <b>/var/www/html/item.php</b> on line <b>14</b><br />',
    'attack_a_php_deprecation_notice_migration_gu': 'Warning: the following oci_ functions are deprecated and will be removed in PHP 9: oci_internal_debug(), oci_password_change() with four arguments, and the OCI-Lob alias class.',
    'attack_a_phpinfo_page_or_any_config_diagnost': '<tr><td class="e">Warning</td><td class="v">oci8.privileged_connect is disabled; oci_pconnect will fall back</td></tr>',
    'attack_a_product_catalogue_json_dpy_plus_fo': '{"orders": [{"ref": "ORA-00042", "sku": "DPY-1200", "desc": "Dimmer pack"}, {"ref": "ORA-00043", "sku": "DPY-4410"}]}',
    'attack_a_provider_faq_or_a_net_data_access_c': 'Q: Which exception type is thrown? A: System.Data.SQLite.SQLiteException, which exposes a ResultCode property. The Microsoft.Data.Sqlite provider throws SqliteException instead; the two packages are unrelated despite the similar names.',
    'attack_a_rails_guide_or_an_upgrade_post_the': 'Adapter-level failures are wrapped. ActiveRecord::StatementInvalid (the parent of most of them) carries the original adapter exception as its cause, so you will see SQLite3::SQLException, Mysql2::Error or PG::SyntaxError depending on your database.',
    'attack_a_search_filter_endpoint_with_its_own': '{"error": {"type": "query_parse_error", "reason": "unrecognized token: \\"\'\\" at position 12", "query": "status:open AND name:\'"}}',
    'attack_a_search_filter_endpoint_with_its_own_2': '{"csp-report": {"document-uri": "https://app.example.com/search?q=%27", "violated-directive": "script-src", "blocked-uri": "...", "script-sample": "unrecognized token: \\"\'\\""}}',
    'attack_a_sentry_rollbar_glitchtip_issue_list': '<tr><td>OperationalError at /api/v2/orders</td><td>142 events</td><td>3m ago</td></tr>\n<tr><td>IntegrityError at /signup</td><td>9 events</td><td>2h ago</td></tr>',
    'attack_a_spring_boot_actuator_health_respons': '{"status": "DOWN", "components": {"db": {"status": "DOWN", "details": {"error": "org.springframework.jdbc.BadSqlGrammarException: PreparedStatementCallback; bad SQL grammar [ALTER TABLE audit ADD COLUMN trace_id uuid]; migration V42 not applied"}}}}',
    'attack_a_spring_tutorial_baeldung_style_or_s': '<pre>PreparedStatementCallback; bad SQL grammar [SELECT * FROM usr WHERE id = ?]; nested exception is ...</pre>',
    'attack_a_sqlalchemy_faq_or_how_to_read_an_or': 'The exception message has three parts: the parenthesised DBAPI exception, then the statement under <code>[SQL: ...]</code>, then the parameters under <code>[parameters: ...]</code>, then a short link to the error code page.',
    'attack_a_t_sql_beginners_tutorial_it_also_fi': "Forget a comma in the column list and the parser stops at the next identifier, so you get Incorrect syntax near 'FROM'. The message points at FROM but the real mistake is one line above.",
    'attack_a_t_sql_linter_validator_api_a_web_sq': '{"lint": [{"line": 3, "rule": "T-SQL/parse", "message": "Incorrect syntax near \'FROM\'. Did you mean SELECT?"}], "valid": false}',
    'attack_a_ten_sqlite3_errors_and_what_they_me': '<p><b>sqlite3.OperationalError: no such table</b> &mdash; you forgot to run the schema, or you are pointed at a different file than you think.</p>\n<p><b>sqlite3.IntegrityError: UNIQUE constraint failed</b> &mdash; you inserted a duplicate.</p>',
    'attack_a_waf_security_middleware_block_page_': '{"blocked": true, "rule_id": "942100", "engine": "libinjection", "signature": "Unclosed quotation mark after the character string \'", "request_id": "a91f"}',
    'attack_an_advanced_search_syntax_help_page_o': '<pre>{"code":"BAD_QUERY","error":"unrecognized token: \\"NEAR\\""}</pre>',
    'attack_an_analytics_report_builder_that_expo': '<div class="alert alert-danger">Filter could not be parsed: near "AND": syntax error &mdash; check your expression.</div>',
    'attack_an_error_code_manifest_endpoint_and_a': '{"x-error-codes": ["ERR_SQLITE_ERROR", "SQLite3::SQLException", "psycopg2.errors.SyntaxError", "org.sqlite.SQLiteException", "SqliteError"], "note": "see /docs/errors"}',
    'attack_an_error_code_manifest_endpoint_and_a_2': '{"issues": [{"title": "SQLite3::SQLException: database is locked", "count": 9}, ...]}',
    'attack_an_error_code_manifest_openapi_enum_i': '{"x-error-codes": ["ERR_SQLITE_ERROR", "SQLite3::SQLException", "psycopg2.errors.SyntaxError", "org.sqlite.SQLiteException", "SqliteError"], "note": "see /docs/errors"}',
    'attack_an_error_code_reference_table_sqlite_': '<tr><td>SQLITE_ERROR: Generic error, or a SQL error or missing database</td></tr>\n<tr><td>SQLITE_BUSY: The database file is locked</td></tr>',
    'attack_an_error_tracking_api_listing_the_app': '{"issues": [{"title": "psycopg2.errors.SyntaxError: syntax error at or near \\")\\"", "culprit": "reports.build_pivot", "count": 22}, ...]}',
    'attack_an_error_tracking_observability_api_t': '{"issues": [{"title": "OperationalError at /api/v1/orders", "count": 412, "level": "error"}, {"title": "ActiveRecord::StatementInvalid: PG::ConnectionBad", "count": 8}, {"title": "java.sql.SQLTimeoutException", "count": 3}, ...]}',
    'attack_an_error_tracking_observability_api_t_2': 'OpenAPI: "enum": ["PDOException", "java.sql.SQLException", ...]',
    'attack_an_eslint_report_rendered_in_a_ci_das': '/app/node_modules/sequelize/lib/dialects/postgres/query.js:185:27  warning  Unexpected console statement  no-console\n/app/node_modules/sequelize/lib/dialects/sqlite/query.js:183:12  warning  Unexpected console statement  no-console',
    'attack_an_issue_list_json_the_report_chose_t': '{"issues": [..., {"title": "org.hibernate.exception.GenericJDBCException: could not prepare statement [pool exhausted]", "count": 2}]}',
    'attack_an_issue_list_or_job_status_json_the_': '{"issues": [..., {"title": "An exception occurred while executing the nightly rollup", "count": 1}]}',
    'attack_an_observability_issue_list_json_the_': '{"issues": [..., {"title": "ActiveRecord::StatementInvalid: PG::ConnectionBad", "count": 8}, ...]}',
    'attack_an_observability_issue_list_json_the__2': '{"issues": [{"title": "SQLGrammarException: could not extract ResultSet", "last_seen": "2026-09-01", "count": 5}, {"title": "Uncaught mysqli_sql_exception in cron/rollup.php", "count": 3}]}',
    'attack_an_odbc_connectivity_troubleshooting_': "<pre>[Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Login failed for user 'reporting'.</pre>",
    'attack_an_openapi_json_schema_document_serve': '{"components": {"schemas": {"DbError": {"properties": {"exception": {"enum": ["PDOException", "java.sql.SQLException", "Microsoft.Data.SqlClient.SqlException", "com.mysql.cj.jdbc.exceptions.MySQLSyntaxErrorException", "com.microsoft.sqlserver.jdbc.SQLServerException", "org.hibernate.exception.GenericJDBCException", "SequelizeDatabaseError", "System.Data.SQLite.SQLiteException"]}}}}}}',
    'attack_an_upgrade_md_migration_guide_which_i': '<li>Doctrine\\DBAL\\Exception\\DriverException is no longer thrown directly; use the specific subclasses.</li>\n<li>The message prefix "An exception occurred while executing" is unchanged, but the statement is no longer interpolated into it.</li>',
    'attack_any_connecting_python_to_oracle_tutor': '<pre>try:\n    cursor.execute(sql, params)\nexcept cx_Oracle.DatabaseError as e:\n    log.warning("database unavailable, retrying")\nexcept oracledb.exceptions.OperationalError:\n    reconnect()\n</pre>',
    'attack_any_ruby_code_sample_on_a_docs_page_g': '<pre>begin\n  Order.connection.execute(sql)\nrescue SQLite3::SQLException =&gt; e\n  Rails.logger.warn(e.message)\nend</pre>',
    'attack_any_sqlite_with_spring_boot_tutorial': 'spring.datasource.url=jdbc:sqlite:/var/data/app.db\nspring.datasource.driver-class-name=org.sqlite.JDBC\nspring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect',
    'attack_dataerror_and_integrityerror_are_val': 'No handler DataError at /reports was registered.\n\nand: IntegrityError at /reports is not a known view name.',
    'attack_every_java_jdbc_tutorial_every_code_s': 'import java.sql.PreparedStatement;\nimport java.sql.SQLException;\n\npublic class Demo {\n  public static void main(String[] a) throws java.sql.SQLException {',
    'attack_hibernate_s_package_summary_javadoc_e': '<tr><td>org.hibernate.exception.DataException</td><td>Implementation of JDBCException indicating that evaluation of the SQL statement failed due to the supplied data.</td></tr>\n<tr><td>org.hibernate.exception.SQLGrammarException</td><td>Implementation of JDBCException indicating that the SQL sent to the database server was invalid.</td></tr>',
    'attack_nodejs_org_api_errors_html_the_node_j': '<h3><code>ERR_SQLITE_ERROR</code></h3>\n<p>An error was returned by <a href="/api/sqlite.html">SQLite</a>. Added in: v22.5.0.</p>',
    'attack_parameter_can_forge_correctly_refuses': '<form action="/search.php" method="get">\n  <input type="hidden" name="ORA-00933" value="1">\n  <input type="text" name="q" value="apple&#039;">\n</form>',
    'attack_php_net_s_pdoexception_class_page_and': 'If you instead see SQLSTATE[HY000] [1045] Access denied, the password in .env drifted from the one baked into the volume; drop the volume and let it re-seed.\nPDOException is thrown either way, so catching it tells you nothing on its own.',
    'attack_php_net_s_upgrading_file_every_php_8_': 'The default error reporting mode is now <code>MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT</code>. Previously the extension emitted a warning and returned <code>false</code>; a failing call now throws <code>mysqli_sql_exception</code>. Wrap your calls in try/catch, or call <code>mysqli_report(MYSQLI_REPORT_OFF)</code> during migration.',
    'attack_produced_live_against_postgres_17_6_p': 'ERROR:  invalid input syntax for type integer: "1\'"\nCONTEXT:  unnamed portal parameter $1 = \'...\'',
    'attack_produced_live_get_http_localhost_3000': 'Did you spot the error message with the `SQLITE_ERROR` and the entire SQL query in the 500 response to `/login`? If not, keep the network tab open and click _Log in_ again.',
    'attack_produced_live_sqlalchemy_2_x_psycopg2': '(psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint "items_name_key"\nDETAIL:  Key (name)=(apple) already exists.\n\n[SQL: INSERT INTO items(id,name) VALUES (%(i)s,%(n)s)]\n[parameters: {\'i\': 99, \'n\': \'apple\'}]\n(Background on this error at: https://sqlalche.me/e/20/gkpj)',
    'attack_produced_live_with_users_goku_erlik_2': '{"error":"sqlite3.IntegrityError: UNIQUE constraint failed: t.a"}',
    'attack_reachable_two_ways_the_lane_controls_': '<p>Filter <code>SQLSTATE[42000]</code> produced no rows.</p>',
    'attack_same_shape_as_the_sqlite3_row_the_mod': 'Invalid parameter psycopg2.errors.SyntaxError: syntax error in filter expression\n\nand: Invalid parameter asyncpg.exceptions.QueryError: syntax error in filter expression',
    'attack_sequelize_s_own_errors_documentation_': '<li><code>SequelizeDatabaseError</code> &mdash; thrown when the database returns an error.</li>\n<li><code>SequelizeUniqueConstraintError</code> &mdash; thrown on a unique index violation; carries the offending fields.</li>',
    'attack_spring_s_own_reference_documentation_': "A malformed statement surfaces as org.springframework.jdbc.BadSqlGrammarException rather than java.sql.SQLException, and a JPA provider's equivalent surfaces as org.springframework.dao.InvalidDataAccessResourceUsageException.",
    'attack_the_colon_that_agent_3_called_the_dis': '{"errors":[{"field":"sqlite3.OperationalError","message":"unknown query parameter"}]}\nInvalid parameter sqlite3.OperationalError: expected integer, got string',
    'attack_the_database_engine_events_and_errors': "<tr><td>105</td><td>15</td><td>Unclosed quotation mark after the character string '%.*ls'.</td></tr>",
    'attack_the_microsoft_jdbc_driver_s_javadoc_m': '<h2>Class com.microsoft.sqlserver.jdbc.SQLServerException</h2>\n<pre>public final class SQLServerException extends java.sql.SQLException</pre>\n<p>Represents the exception thrown from any point in the driver that throws a java.sql.SQLException.</p>',
    'attack_the_odp_net_api_reference_on_docs_ora': '<p>The Oracle.ManagedDataAccess.Client.OracleException class represents an exception that is thrown when ODP.NET returns a warning or error from the database.</p>',
    'attack_the_openapi_error_type_enum_above_the': 'OpenAPI enum entry: "com.microsoft.sqlserver.jdbc.SQLServerException"',
    'attack_the_openapi_error_type_enum_this_one_': 'OpenAPI enum entry: "SequelizeDatabaseError"',
    'attack_the_php_net_manual_page_for_pg_query_': '<pre>Warning: pg_query(): Query failed: ERROR:  relation "user" does not exist in /var/www/db.php on line 12</pre>',
    'attack_the_same_changelog_issue_list_genre_w': '<li>DPY-2041 &mdash; rolled back the canary deploy job that never drained</li>\n<li>DPY-1998 &mdash; pin the build image digest</li>',
    'attack_the_same_openapi_error_type_enum_and_': 'OpenAPI enum entry: "Microsoft.Data.SqlClient.SqlException"',
    'attack_the_same_openapi_error_type_enum_and__2': 'hidden form field: <input type="hidden" name="driver" value="System.Data.SqlClient">',
    'attack_the_sqlexception_tostring_api_referen': 'Returns a string that includes the class name, the message, the stack trace, and a trailing diagnostic block of the form Error Number:105,State:1,Class:15 followed by the ClientConnectionId.',
    'attack_this_is_the_lane_inflicting_it_on_its': '<b>Warning</b>:  Undefined array key "pg_num" in <b>/var/www/html/list.php</b> on line <b>9</b><br />\n\nand, for the proposed OCI alternative:\n<b>Warning</b>:  Undefined array key "filters[oci_id]" in <b>/var/www/html/list.php</b> on line <b>9</b><br />',
    'attack_three_separate_machine_output_shapes_': '{"errors": [{"code": "ORA-00001", "message": "unique constraint violated", "handled": true}, {"code": "ORA-01756", "retryable": false}, {"code": "DPY-2041", "source": "driver"}], "sqlstate": null}',
    'attack_three_separate_machine_output_shapes__2': '{"orders": [{"ref": "ORA-00042", "sku": "DPY-1200", "desc": "Dimmer pack"}]}',
    'attack_three_separate_machine_output_shapes__3': '{"status": 404, "known_routes": ["GET /api/v1/db/errors/ora-01756", "POST /internal/pdo-exception-replay", "GET /debug/sqlstate"]}',
    'fixture_api_json': '{"sqlstate": null, "rows": 0, "error": null}',
    'fixture_changelog': '<li>Fixed: pg_query() calls are now parameterised (see #412)</li>',
    'fixture_changelog_mysql': '<li>Deprecated: mysql_fetch_array() is removed in 8.0; use mysqli_fetch_assoc() instead.</li>',
    'fixture_docs_ora': '<p>See ORA-01756 in the Oracle reference for quoting rules.</p>',
    'fixture_error_reference': '<p>SQLSTATE values are five characters long. The ORA prefix is used by Oracle for its own error codes.</p>',
    'fixture_form_hint': '<label>Query</label><span class="hint">Check your SQL syntax before submitting.</span>',
    'fixture_hidden_input': '<input type="hidden" name="sqlstate" value="">',
    'fixture_juice_shop_bundle': '{text:"Did you spot the error message with the `SQLITE_ERROR` and the entire SQL query in the 500 response?",solved:!1}',
    'fixture_route_listing': '{"routes": ["/api/sqlite3/status", "/api/mysql/health"]}',
    'fixture_sql_tutorial': '<h1>Learn SQL</h1><p>This chapter explains SQL syntax for beginners, including SELECT, WHERE and JOIN.</p>',
    'fixture_unrelated_warning': '<b>Warning</b>:  Undefined array key "password" in /var/www/html/vulnerabilities/brute/source/low.php on line 12',
    'synthesis_must_not_match': 'ERROR:  invalid input syntax for type integer: "1\'"',
    'synthesis_must_not_match_10': '<li>ORA-01756 &mdash; reduced cold-start latency on the orders service</li>',
    'synthesis_must_not_match_11': '<b>Warning</b>:  Undefined array key "pg_num" in <b>/var/www/html/list.php</b> on line <b>9</b><br />',
    'synthesis_must_not_match_12': 'Invalid parameter sqlite3.OperationalError: expected integer, got string',
    'synthesis_must_not_match_13': 'Invalid parameter ORA-00933: expected integer, got string',
    'synthesis_must_not_match_14': '<title>OperationalError at /orders/</title>',
    'synthesis_must_not_match_15': '<pre class="exception_value">connection to server at "db" (10.0.3.2), port 5432 failed: Connection refused</pre>',
    'synthesis_must_not_match_16': '(psycopg2.errors.UniqueViolation) duplicate key value violates unique constraint "items_name_key"',
    'synthesis_must_not_match_17': "[parameters: {'i': 99, 'n': 'apple'}]",
    'synthesis_must_not_match_18': '(Background on this error at: https://sqlalche.me/e/20/gkpj)',
    'synthesis_must_not_match_19': '{"status":"DOWN","components":{"db":{"details":{"error":"org.springframework.jdbc.BadSqlGrammarException: PreparedStatementCallback; bad SQL grammar [ALTER TABLE audit ADD COLUMN trace_id uuid]"}}}}',
    'synthesis_must_not_match_2': "CONTEXT:  unnamed portal parameter $1 = '...'",
    'synthesis_must_not_match_20': "you have an error in your sql syntax; check the manual that corresponds to your mysql server version for the right syntax to use near 'x' at line 1",
    'synthesis_must_not_match_21': 'GET /api/v1/db/errors/ora-01756',
    'synthesis_must_not_match_3': "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%s' at line 1",
    'synthesis_must_not_match_4': '{"blocked":true,"rule_id":"942100","signature":"Unclosed quotation mark after the character string \'"}',
    'synthesis_must_not_match_5': '{"code":"BAD_QUERY","error":"unrecognized token: \\"NEAR\\""}',
    'synthesis_must_not_match_6': 'Did you spot the error message with the `SQLITE_ERROR` and the entire SQL query in the 500 response to `/login`?',
    'synthesis_must_not_match_7': '{"components":{"schemas":{"DbError":{"properties":{"exception":{"enum":["PDOException","java.sql.SQLException","com.microsoft.sqlserver.jdbc.SQLServerException","SequelizeDatabaseError"]}}}}}}',
    'synthesis_must_not_match_8': '{"errors":[{"code":"ORA-00001","message":"unique constraint violated","handled":true},{"code":"DPY-2041","source":"driver"}]}',
    'synthesis_must_not_match_9': '{"orders":[{"ref":"ORA-00042","sku":"DPY-1200","desc":"Dimmer pack"}]}',
}


# Bodies the PATTERN cannot separate from a finding, and which only the
# comparison drops. They are here rather than in BENIGN_BODIES because the
# pattern matching them is the honest answer — the bytes really are identical to
# a real error — and because the layering is worth testing rather than assuming.
#
# Each is a page that reads the SAME before and after the payload, so the
# response cannot be evidence about the payload. test_sql_error_detector.py
# serves them and asserts the case reports nothing.
PATTERN_CANNOT_SEPARATE = {
    'stack_overflow_psycopg_title': '<title>python - psycopg2.errors.SyntaxError: syntax error at or near "ON" - Stack Overflow</title>\n<h1>psycopg2.errors.SyntaxError: syntax error at or near "ON"</h1>',
    'stack_overflow_php_warning_title':
        '<title>php - Warning: mysqli_fetch_assoc() expects parameter 1 to be mysqli_result, '
        'boolean given - Stack Overflow</title>',
    'changelog_quoting_the_php_warning':
        '<li>Fixed: mysqli_fetch_assoc() expects parameter 1 to be mysqli_result warnings on '
        'the reports page (#812)</li>',
}
