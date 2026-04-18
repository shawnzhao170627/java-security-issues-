// [VULNERABLE] 文件说明：演示 SQL 注入漏洞，仅用于教学目的
// 漏洞类型：SQL-INJECTION
// 风险等级：critical
// 对应文档：docs/vulnerabilities/injection/sql-injection.md

/**
 * 漏洞代码示例：SQL 注入
 * Vulnerable Code Example: SQL Injection
 */
public class SqlInjectionVulnerable {

    /**
     * 漏洞：JDBC 字符串拼接
     * Vulnerability: JDBC String Concatenation
     */
    public User findByUsername(String username) throws SQLException {
        Connection conn = dataSource.getConnection();
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);

        if (rs.next()) {
            User user = new User();
            user.setId(rs.getLong("id"));
            user.setUsername(rs.getString("username"));
            user.setEmail(rs.getString("email"));
            return user;
        }
        return null;
    }

    /**
     * 漏洞：动态排序字段拼接
     * Vulnerability: Dynamic Order By Injection
     */
    public List<User> findUsers(String sortBy, String order) throws SQLException {
        Connection conn = dataSource.getConnection();
        String sql = "SELECT * FROM users ORDER BY " + sortBy + " " + order;
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);

        List<User> users = new ArrayList<>();
        while (rs.next()) {
            User user = new User();
            user.setId(rs.getLong("id"));
            user.setUsername(rs.getString("username"));
            users.add(user);
        }
        return users;
    }
}
