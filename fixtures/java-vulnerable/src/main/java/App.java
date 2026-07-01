package fixtures;

import java.io.*;
import java.sql.*;
import java.util.Map;

public class App {

    // DK-JAVA-001: SQL injection via string concatenation
    public Map<String, Object> getUser(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        Statement stmt = conn.createStatement();
        // Vulnerable: user input directly in SQL query
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
        return Map.of("found", rs.next());
    }

    public Map<String, Object> searchUsers(String query) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        Statement stmt = conn.createStatement();
        // Another SQL injection via String.format
        String sql = String.format("SELECT * FROM users WHERE name LIKE '%%%s%%'", query);
        ResultSet rs = stmt.executeQuery(sql);
        return Map.of("count", 0);
    }

    // DK-JAVA-003: Empty catch blocks swallowing errors
    public void processFile(String path) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(path));
            String line = reader.readLine();
            // process line
        } catch (Exception e) {
            // Empty catch — error silently swallowed
        }
    }

    public void connectDatabase() {
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
            conn.prepareStatement("SELECT 1").execute();
        } catch (SQLException e) {
            // Another empty catch
        }
    }

    // DK-JAVA-002: Unsafe deserialization
    public Object deserializeUser(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        // Vulnerable: deserializing untrusted data
        return ois.readObject();
    }
}
