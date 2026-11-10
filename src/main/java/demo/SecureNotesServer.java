package demo;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/** A dependency-free demonstration of secure service patterns. */
public final class SecureNotesServer {
    private static final int MAX_BODY_BYTES = 8_192;
    private static final Pattern USERNAME = Pattern.compile("[a-zA-Z0-9_]{3,24}");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, Account> ACCOUNTS = new ConcurrentHashMap<>();
    private static final Map<String, String> SESSIONS = new ConcurrentHashMap<>();
    private static final Map<String, String> NOTES = new ConcurrentHashMap<>();

    private SecureNotesServer() {}

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/register", SecureNotesServer::register);
        server.createContext("/login", SecureNotesServer::login);
        server.createContext("/note", SecureNotesServer::note);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("!Secure Notes demo listening on http://127.0.0.1:" + port);
    }

    private static void register(HttpExchange x) throws IOException {
        if (!method(x, "POST")) return;
        Map<String, String> form = readForm(x);
        String user = form.getOrDefault("username", "");
        String password = form.getOrDefault("password", "");
        if (!USERNAME.matcher(user).matches() || password.length() < 12 || password.length() > 128) {
            respond(x, 400, "{\"error\":\"invalid username or password policy\"}"); return;
        }
        byte[] salt = new byte[16]; RANDOM.nextBytes(salt);
        Account account = new Account(salt, derive(password.toCharArray(), salt));
        if (ACCOUNTS.putIfAbsent(user, account) != null) {
            respond(x, 409, "{\"error\":\"account unavailable\"}"); return;
        }
        respond(x, 201, "{\"status\":\"created\"}");
    }

    private static void login(HttpExchange x) throws IOException {
        if (!method(x, "POST")) return;
        Map<String, String> form = readForm(x);
        String user = form.getOrDefault("username", "");
        String password = form.getOrDefault("password", "");
        Account account = ACCOUNTS.get(user);
        // Keep the response generic so callers cannot enumerate registered usernames.
        if (account == null || !java.security.MessageDigest.isEqual(account.hash, derive(password.toCharArray(), account.salt))) {
            respond(x, 401, "{\"error\":\"invalid credentials\"}"); return;
        }
        byte[] tokenBytes = new byte[32]; RANDOM.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        SESSIONS.put(token, user);
        x.getResponseHeaders().set("Set-Cookie", "sid=" + token + "; HttpOnly; SameSite=Strict; Path=/");
        respond(x, 200, "{\"status\":\"authenticated\"}");
    }

    private static void note(HttpExchange x) throws IOException {
        String user = authenticatedUser(x);
        if (user == null) { respond(x, 401, "{\"error\":\"authentication required\"}"); return; }
        if ("POST".equals(x.getRequestMethod())) {
            Map<String, String> form = readForm(x);
            String body = form.getOrDefault("text", "");
            if (body.isBlank() || body.length() > 1_000) { respond(x, 400, "{\"error\":\"invalid note\"}"); return; }
            NOTES.put(user, body);
            respond(x, 201, "{\"status\":\"saved\"}");
        } else if ("GET".equals(x.getRequestMethod())) {
            // Object lookup is always scoped to the authenticated principal (IDOR protection).
            String value = NOTES.getOrDefault(user, "");
            respond(x, 200, "{\"note\":\"" + jsonEscape(value) + "\"}");
        } else {
            x.getResponseHeaders().set("Allow", "GET, POST"); respond(x, 405, "{\"error\":\"method not allowed\"}");
        }
    }

    private static String authenticatedUser(HttpExchange x) {
        String cookie = x.getRequestHeaders().getFirst("Cookie");
        if (cookie == null) return null;
        for (String part : cookie.split(";")) {
            String[] pair = part.trim().split("=", 2);
            if (pair.length == 2 && pair[0].equals("sid")) return SESSIONS.get(pair[1]);
        }
        return null;
    }

    private static Map<String, String> readForm(HttpExchange x) throws IOException {
        long declared = -1;
        try { declared = Long.parseLong(x.getRequestHeaders().getFirst("Content-length")); } catch (Exception ignored) {}
        if (declared > MAX_BODY_BYTES) throw new IOException("request too large");
        byte[] bytes = x.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
        if (bytes.length > MAX_BODY_BYTES) throw new IOException("request too large");
        Map<String, String> values = new java.util.HashMap<>();
        for (String item : new String(bytes, StandardCharsets.UTF_8).split("&")) {
            String[] pair = item.split("=", 2);
            if (pair.length == 2) values.put(java.net.URLDecoder.decode(pair[0], StandardCharsets.UTF_8), java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
        }
        return values;
    }

    private static byte[] derive(char[] password, byte[] salt) {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, 210_000, 256);
            byte[] result = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            java.util.Arrays.fill(password, '\0');
            return result;
        } catch (Exception e) { throw new IllegalStateException("password hashing unavailable", e); }
    }

    private static boolean method(HttpExchange x, String expected) throws IOException {
        if (expected.equals(x.getRequestMethod())) return true;
        x.getResponseHeaders().set("Allow", expected); respond(x, 405, "{\"error\":\"method not allowed\"}"); return false;
    }

    private static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private static void respond(HttpExchange x, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        x.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        x.getResponseHeaders().set("Cache-Control", "no-store");
        x.sendResponseHeaders(status, bytes.length);
        try (var out = x.getResponseBody()) { out.write(bytes); }
    }

    private record Account(byte[] salt, byte[] hash) {}
}
