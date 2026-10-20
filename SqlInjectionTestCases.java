// File: SqlInjectionTestCases.java
// SAST TEST FILE - intentionally vulnerable patterns for scanner evaluation.
// Do NOT deploy or execute. Each method is labeled with an expected result.
package sast.testcases.sqli;

import java.sql.*;
import java.util.Map;
import org.hibernate.Session;

public class SqlInjectionTestCases {

    private Connection conn;
    private Session hibernateSession;

    // SAST-TEST: CWE-89 | EXPECT: FINDING | CASE: concat-statement
    public ResultSet case01_concatStatement(String userInput) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + userInput);
    }

    // SAST-TEST: CWE-89 | EXPECT: FINDING | CASE: string-format
    public ResultSet case02_stringFormat(String userInput) throws SQLException {
        String sql = String.format("SELECT * FROM users WHERE name = '%s'", userInput);
        return conn.createStatement().executeQuery(sql);
    }

    // SAST-TEST: CWE-89 | EXPECT: FINDING | CASE: stringbuilder-append
    public ResultSet case03_stringBuilder(String userInput) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM orders WHERE customer = ");
        sb.append(userInput);
        return conn.createStatement().executeQuery(sb.toString());
    }

    // SAST-TEST: CWE-89 | EXPECT: FINDING | CASE: hql-concat
    public Object case04_hqlConcat(String userInput) {
        return hibernateSession.createQuery("FROM User u WHERE u.email = '" + userInput + "'").list();
    }

    // SAST-TEST: CWE-89 | EXPECT: FINDING | CASE: second-order
    // Value is read from the database (trusted-looking) and then concatenated.
    public ResultSet case05_secondOrder(int userId) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT nickname FROM profiles WHERE user_id = ?");
        ps.setInt(1, userId);
        ResultSet rs = ps.executeQuery();
        rs.next();
        String nickname = rs.getString("nickname");
        return conn.createStatement().executeQuery(
            "SELECT * FROM audit_log WHERE actor = '" + nickname + "'");
    }

    // SAST-TEST: CWE-89 | EXPECT: FINDING | CASE: concat-through-helper
    public ResultSet case06_helperPassThrough(String userInput) throws SQLException {
        String filter = buildFilter(userInput);
        return conn.createStatement().executeQuery("SELECT * FROM products " + filter);
    }
    private String buildFilter(String value) {
        return "WHERE category = '" + value + "'";
    }

    // SAST-TEST: CWE-89 | EXPECT: NO_FINDING | CASE: prepared-statement
    public ResultSet case07_preparedStatement(String userInput) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userInput);
        return ps.executeQuery();
    }

    // SAST-TEST: CWE-89 | EXPECT: NO_FINDING | CASE: hql-named-parameter
    public Object case08_hqlParameter(String userInput) {
        return hibernateSession.createQuery("FROM User u WHERE u.email = :email")
            .setParameter("email", userInput).list();
    }

    // SAST-TEST: CWE-89 | EXPECT: NO_FINDING | CASE: allowlisted-order-by
    // User input selects a key from a fixed map; the SQL fragment is never user-controlled.
    private static final Map<String, String> SORT_COLUMNS =
        Map.of("name", "name", "date", "created_at");

    public ResultSet case09_allowlistOrderBy(String sortKey) throws SQLException {
        String column = SORT_COLUMNS.getOrDefault(sortKey, "id");
        return conn.createStatement().executeQuery("SELECT * FROM items ORDER BY " + column);
    }

    // SAST-TEST: CWE-89 | EXPECT: NO_FINDING | CASE: constant-concat
    public ResultSet case10_constantConcat() throws SQLException {
        return conn.createStatement().executeQuery(
            "SELECT * FROM users WHERE active = " + 1);
    }
}
