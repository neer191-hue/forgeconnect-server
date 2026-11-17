import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class AuthServer {
    private static final File DB_FILE = new File("forgeconnect_users.properties");
    private static final Properties db = new Properties();
    private static final Map<String, Session> sessions = new ConcurrentHashMap<>();

    static class Session {
        final String user;
        final String ip;
        volatile boolean approved = false;

        Session(String user, String ip) {
            this.user = user;
            this.ip = ip;
        }
    }

    public static void main(String[] args) throws Exception {
        if (DB_FILE.exists()) {
            try (FileInputStream in = new FileInputStream(DB_FILE)) {
                db.load(in);
            }
        }

                int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", AuthServer::handleHome);
        server.createContext("/auth", AuthServer::handleAuth);
        server.createContext("/approve", AuthServer::handleApprove);
        server.createContext("/status", AuthServer::handleStatus);
        server.setExecutor(null);
        server.start();

        System.out.println("[ForgeConnect] Global Auth Server LIVE on port 8080!");
    }

    private static void handleHome(HttpExchange ex) throws IOException {
        String html = "<html><body style='font-family:sans-serif;background:#111;color:#eee;padding:40px;'>"
                + "<h1>ForgeConnect Global Authentication</h1>"
                + "<p>Status: <b style='color:#4ade80;'>ONLINE</b></p>"
                + "<p>Protected Accounts: <b>" + db.size() + "</b></p>"
                + "</body></html>";
        send(ex, 200, "text/html", html);
    }

    private static void handleAuth(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
        String user = q.getOrDefault("user", "").toLowerCase().trim();
        String ip = q.getOrDefault("ip", "").trim();

        if (user.isEmpty() || ip.isEmpty()) {
            send(ex, 400, "text/plain", "INVALID");
            return;
        }

        synchronized (db) {
            String savedIp = db.getProperty(user);
            if (savedIp == null) {
                db.setProperty(user, ip);
                saveDb();
                System.out.println("[AUTO-LINKED] " + user + " -> " + ip);
                send(ex, 200, "text/plain", "ALLOW");
                return;
            }
            if (savedIp.equals(ip)) {
                System.out.println("[ALLOW] " + user + " (" + ip + ")");
                send(ex, 200, "text/plain", "ALLOW");
            } else {
                String token = UUID.randomUUID().toString().substring(0, 10);
                sessions.put(token, new Session(user, ip));
                System.out.println("[PENDING] " + user + " from new IP " + ip + " | Token: " + token);
                send(ex, 200, "text/plain", "VERIFY:" + token);
            }
        }
    }

    private static void handleApprove(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
        String token = q.get("token");
        Session session = (token != null) ? sessions.get(token) : null;

        if (session == null) {
            send(ex, 400, "text/html", "<h2>Link expired or invalid. Rejoin the server for a new link.</h2>");
            return;
        }

        session.approved = true;
        synchronized (db) {
            db.setProperty(session.user, session.ip);
            saveDb();
        }
        System.out.println("[VERIFIED] " + session.user + " approved new IP " + session.ip);
        send(ex, 200, "text/html", "<h2 style='font-family:sans-serif;color:#16a34a;'>Verified! Switch back to Minecraft—you are now unlocked!</h2>");
    }

    private static void handleStatus(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
        String token = q.get("token");
        Session session = (token != null) ? sessions.get(token) : null;
        if (session != null && session.approved) {
            sessions.remove(token);
            send(ex, 200, "text/plain", "APPROVED");
        } else {
            send(ex, 200, "text/plain", "PENDING");
        }
    }

    private static void saveDb() {
        try (FileOutputStream out = new FileOutputStream(DB_FILE)) {
            db.store(out, "ForgeConnect Users");
        } catch (IOException ignored) {
        }
    }

    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> map = new HashMap<>();
        if (raw == null || raw.isEmpty()) {
            return map;
        }
        for (String p : raw.split("&")) {
            int eq = p.indexOf('=');
            if (eq > 0) {
                String k = URLDecoder.decode(p.substring(0, eq), StandardCharsets.UTF_8);
                String v = URLDecoder.decode(p.substring(eq + 1), StandardCharsets.UTF_8);
                map.put(k, v);
            }
        }
        return map;
    }

    private static void send(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type + "; charset=UTF-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}
