package burp;

import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.sqlite.SQLiteConfig;

public class Database {
    //private Config config;

    private Connection connection = null;
    private PreparedStatement preparedStatement = null;
    private IBurpExtenderCallbacks burpExtenderCallbacks;
    private String dbFile;
    private boolean debug;
    private Hash hash;

    Database(IBurpExtenderCallbacks b) {
        this.dbFile = "burp-free-hash";
        this.debug = true;
        this.hash = new Hash();
        this.burpExtenderCallbacks = b;
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            this.burpExtenderCallbacks.printError(e.toString());
        }
    }

    /*boolean close() {
        try {
            if (this.connection != null) {
                this.connection.close();
            }
            return true;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError(e.getMessage());
            return false;
        }
    }

    private Connection getConnection() {
        SQLiteConfig sqliteConfig = new SQLiteConfig();
        sqliteConfig.setEncoding(SQLiteConfig.Encoding.UTF_8);
        Connection connection;
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:"+this.dbFile, sqliteConfig
                    .toProperties());
            this.burpExtenderCallbacks.printError("DB: Opened database file: " + this.dbFile);
            return connection;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError(e.getMessage());
            return null;
        }
    }

    boolean init() {
        Statement statement = null;
        try {
            if (this.connection == null) {
                this.connection = getConnection();
            }
            statement = this.connection.createStatement();
            statement.setQueryTimeout(30);
            this.burpExtenderCallbacks.printError(" + Rebuilding all DB tables.");
            String sqlDropTables = "DROP TABLE IF EXISTS params; DROP TABLE IF EXISTS hashes; DROP TABLE IF EXISTS algorithms;";
            statement.executeUpdate(sqlDropTables);
            String sqlCreateAlgoTable = "CREATE TABLE algorithms (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, Name TEXT NOT NULL)";
            statement.executeUpdate(sqlCreateAlgoTable);
            String sqlCreateParamTable = "CREATE TABLE params (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, value TEXT NOT NULL)";
            statement.executeUpdate(sqlCreateParamTable);
            String sqlCreateHashTable = "CREATE TABLE hashes (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, algorithmID INTEGER NOT NULL, paramID INTEGER, value TEXT NOT NULL)";
            statement.executeUpdate(sqlCreateHashTable);
            this.burpExtenderCallbacks.printError(" + Adding " + this.hash.getHashAlgos().size() + " hash algorithms to DB.");
            Collections.reverse(this.hash.getHashAlgos());
            String sql_insertAlgo = "INSERT OR REPLACE INTO algorithms(name ) VALUES (? )";
            for (String algo : this.hash.getHashAlgos()) {
                this.preparedStatement = this.connection.prepareStatement(sql_insertAlgo);
                this.preparedStatement.setString(1, algo);
                this.preparedStatement.executeUpdate();
                this.burpExtenderCallbacks.printOutput(" + Adding Hash Algorithm to DB: " + algo);
            }
            Collections.reverse(this.hash.getHashAlgos());
            this.burpExtenderCallbacks.printOutput("DB: Database initialized.");
            return true;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError(e.getMessage());
            return false;
        } catch (Exception ex) {
            this.burpExtenderCallbacks.printError(ex.toString());
        }
        return false;
    }

    boolean saveParam(String paramValue) {
        int paramId = getParamId(paramValue);
        if (paramId > 0) {
            return false;
        }
        try {
            if (this.connection == null) {
                this.connection = getConnection();
            }
            String sqInsertParam = "INSERT OR REPLACE INTO params(value) VALUES (?)";
            this.preparedStatement = this.connection.prepareStatement(sqInsertParam);
            this.preparedStatement.setString(1, paramValue);
            this.preparedStatement.executeUpdate();
            this.burpExtenderCallbacks.printOutput("DB: Saving Discovered Parameter Value: " + paramValue);
            return true;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError(e.getMessage());
        }
        return false;
    }

    int getParamId(String paramValue) {
        try {
            if (this.connection == null) {
                this.connection = getConnection();
            }
            String sql_paramExists = "SELECT * from params where value = ?";
            this.preparedStatement = this.connection.prepareStatement(sql_paramExists);
            this.preparedStatement.setString(1, paramValue);
            ResultSet resultSet = this.preparedStatement.executeQuery();
            if (!resultSet.next()) {
                return 0;
            }
            int id = resultSet.getInt("id");
            if (this.debug) {
                this.burpExtenderCallbacks.printOutput("DB: Found '" + paramValue + "' in the db at index=" + id);
            }
            return id;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError("DB: SQLException: " + e);
        }
        return -1;
    }

    String getParamByHash(HashRecord hash) {
        try {
            if (this.connection == null) {
                this.connection = getConnection();
            }
            String sql_paramExists = "select params.value from hashes inner join params on hashes.paramID=params.ID where hashes.algorithmid = ? and hashes.value = ?";
            this.preparedStatement = this.connection.prepareStatement(sql_paramExists);
            this.preparedStatement.setString(1, Integer.toString(hash.algorithm.id));
            this.preparedStatement.setString(2, hash.getNormalizedRecord());
            ResultSet rs = this.preparedStatement.executeQuery();
            if (!rs.next()) {
                return null;
            }
            String paramValue = rs.getString("value");
            if (this.debug) {
                this.burpExtenderCallbacks.printOutput("DB: Match '" + paramValue + "' for '" + hash.getNormalizedRecord() + "'");
            }
            return paramValue;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError("DB: SQLException: " + e);
        }
        return null;
    }

    boolean saveParamWithHash(ParameterWithHash parmWithHash) {
        int paramId = getParamId(parmWithHash.parameter.value);
        if (paramId <= 0) {
            if (this.debug) {
                this.burpExtenderCallbacks.printOutput("DB: Cannot save hash " + parmWithHash.hashedValue + " until the following parameter is saved " + parmWithHash.parameter.value);
            }
            saveParam(parmWithHash.parameter.value);
            paramId = getParamId(parmWithHash.parameter.value);
        }
        try {
            if (this.connection == null) {
                this.connection = getConnection();
            }
            int algorithmId = this.config.getHashId(parmWithHash.algorithm);
            if (algorithmId <= 0) {
                this.burpExtenderCallbacks.printOutput("DB: Could not locate Algorithm ID for " + parmWithHash.algorithm);
                return false;
            }
            String sqlInsertHash = "INSERT OR REPLACE INTO hashes(algorithmID, paramID, value) VALUES (?, ?, ?)";
            this.preparedStatement = this.connection.prepareStatement(sqlInsertHash);
            this.preparedStatement.setString(1, Integer.toString(algorithmId));
            this.preparedStatement.setString(2, Integer.toString(paramId));
            this.preparedStatement.setString(3, parmWithHash.hashedValue.toLowerCase());
            this.preparedStatement.executeUpdate();
            if (this.debug) {
                this.burpExtenderCallbacks.printOutput("DB: Saved " + parmWithHash.algorithm.text + " hash in db: " + parmWithHash.parameter.value + ":" + parmWithHash.hashedValue);
            }
            return true;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError("DB: SQLException: " + e);
        }
        return false;
    }

    boolean saveHash(HashRecord hash) {
        if (getHashIdByValue(hash.getNormalizedRecord()) > 0) {
            return false;
        }
        try {
            if (this.connection == null) {
                this.connection = getConnection();
            }
            String sqlInsertHash = "INSERT OR REPLACE INTO hashes(algorithmID, value) VALUES (?, ?)";
            this.preparedStatement = this.connection.prepareStatement(sqlInsertHash);
            this.preparedStatement.setString(1, Integer.toString(hash.algorithm.id));
            this.preparedStatement.setString(2, hash.getNormalizedRecord());
            this.preparedStatement.executeUpdate();
            this.burpExtenderCallbacks.printOutput("DB: Saving " + hash.algorithm.name.text + " hash of unknown source value in db: " + hash.getNormalizedRecord());
            return true;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError("DB: SQLException: " + e);
        }
        return false;
    }

    int getHashIdByValue(String hashedValue) {
        try {
            if (this.connection == null) {
                this.connection = getConnection();
            }
            String sqlHashExists = "SELECT * from hashes where value = ?";
            this.preparedStatement = this.connection.prepareStatement(sqlHashExists);
            this.preparedStatement.setString(1, hashedValue);
            ResultSet resultSet = this.preparedStatement.executeQuery();
            if (!resultSet.next()) {
                return 0;
            }
            int id = resultSet.getInt("id");
            if (this.debug) {
                this.burpExtenderCallbacks.printOutput("DB: Found '" + hashedValue + "' in the db at index=" + id);
            }
            return id;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError("DB: SQLException: " + e);
        }
        return -1;
    }

    boolean verify() {
        Statement statement = null;
        ResultSet resultSet = null;
        try {
            if (this.connection == null) {
                this.connection = getConnection();
            }
            statement = this.connection.createStatement();
            statement.setQueryTimeout(30);
            String sql_tableCheck = "SELECT name FROM sqlite_master WHERE type='table' AND name='params';";
            resultSet = statement.executeQuery(sql_tableCheck);
            boolean x = false;
            while (resultSet.next()) {
                x = true;
            }
            return x;
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError("DB: SQLException: " + e);
        }
        return false;
    }

    public List<String> getParamsWithoutHashType(HashAlgorithm algorithm) {
        List<String> params = new ArrayList();

        String sqlSelectMissing = "select ID, VALUE from params where ID not in (select paramID from hashes where hashes.algorithmID = ?)";
        try {
            this.preparedStatement = this.connection.prepareStatement(sqlSelectMissing);
            this.preparedStatement.setString(1, Integer.toString(algorithm.id));
            ResultSet resultSet = this.preparedStatement.executeQuery();
            while (resultSet.next()) {
                String value = resultSet.getString("value");
                params.add(value);
            }
        } catch (SQLException e) {
            this.burpExtenderCallbacks.printError("DB: SQL Exception: " + e);
        }
        return params;
    }*/
}
