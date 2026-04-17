/**
 * 安全代码示例：SQL 注入防护
 * Secure Code Example: SQL Injection Prevention
 */
public class SqlInjectionSecure {

    /**
     * 安全：使用 PreparedStatement 参数化查询
     * Secure: Use PreparedStatement with parameterized query
     */
    public User findByUsername(String username) throws SQLException {
        Connection conn = dataSource.getConnection();
        String sql = "SELECT * FROM users WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, username);
        ResultSet rs = pstmt.executeQuery();

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
     * 安全：动态排序字段使用白名单校验
     * Secure: Use whitelist validation for dynamic order by
     */
    private static final Set<String> ALLOWED_SORT_FIELDS =
        Set.of("id", "username", "email", "created_at");
    private static final Set<String> ALLOWED_ORDERS =
        Set.of("ASC", "DESC");

    public List<User> findUsers(String sortBy, String order) throws SQLException {
        // 白名单校验
        if (!ALLOWED_SORT_FIELDS.contains(sortBy.toLowerCase())) {
            throw new IllegalArgumentException("Invalid sort field");
        }
        if (!ALLOWED_ORDERS.contains(order.toUpperCase())) {
            throw new IllegalArgumentException("Invalid order direction");
        }

        Connection conn = dataSource.getConnection();
        // 排序字段无法参数化，但已通过白名单校验
        String sql = "SELECT * FROM users ORDER BY " + sortBy + " " + order.toUpperCase();
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
