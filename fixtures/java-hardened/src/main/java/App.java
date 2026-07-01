package fixtures;

import java.io.*;
import java.sql.*;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class App {

    private static final Logger LOGGER = Logger.getLogger(App.class.getName());

    // DK-JAVA-001 hardened: parameterized queries
    public Map<String, Object> getUser(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, userId);
        ResultSet rs = stmt.executeQuery();
        return Map.of("found", rs.next());
    }

    public Map<String, Object> searchUsers(String query) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name LIKE ?");
        stmt.setString(1, "%" + query + "%");
        ResultSet rs = stmt.executeQuery();
        return Map.of("count", 0);
    }

    // DK-JAVA-003 hardened: proper error handling with logging
    public void processFile(String path) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(path));
            String line = reader.readLine();
            // process line
        } catch (FileNotFoundException e) {
            LOGGER.log(Level.WARNING, "File not found: " + path, e);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error reading file: " + path, e);
        }
    }

    public void connectDatabase() {
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
            conn.prepareStatement("SELECT 1").execute();
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "Database connection failed", e);
        }
    }

    // DK-JAVA-002 hardened: JSON deserialization instead of Java object deserialization
    public Map<String, String> deserializeUser(String json) throws Exception {
        // Using safe JSON parsing instead of ObjectInputStream
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        return mapper.readValue(json, Map.class);
    }
}
