package org.openlxssh.fixture;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.io.nio2.Nio2ServiceFactoryFactory;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.keyboard.InteractiveChallenge;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.forward.RejectAllForwardingFilter;
import org.apache.sshd.server.session.ServerSession;

/** Test-only MINA public-API authenticator. No protocol implementation or upstream patches. */
public final class FixtureServer implements KeyboardInteractiveAuthenticator, SessionListener, AutoCloseable {
    static final Path ROOT = Path.of("/run/openlxssh-multiprompt");
    static final int MAX_SESSIONS = 8;
    static final int MAX_PENDING = 8;
    static final int MAX_ATTEMPTS = 3;
    static final int TTL_SECONDS = 75;
    static final int AUTH_SECONDS = 90;
    static final Set<String> SCENARIOS = Set.of(
            "two", "zero-accept", "zero-reject", "approval", "reject", "cancel", "timeout");
    private final Object lock = new Object();
    private final SecureRandom random = new SecureRandom();
    private final Map<Session, Integer> sessions = new IdentityHashMap<>();
    private final Map<ServerSession, Attempt> pending = new IdentityHashMap<>();
    private final Map<String, Long> outcomes = new HashMap<>();
    // Admission is limited to MAX_PENDING, with at most two timers per attempt.
    private final ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(2, r -> {
        Thread t = new Thread(r, "fixture-bounded-scheduler");
        t.setDaemon(true);
        return t;
    });
    private boolean closed;
    private long generated;
    private long responseCallbacks;
    private long zeroResponseCallbacks;
    private long ignoredLateResults;

    static final class Attempt {
        final String id;
        final String scenario;
        final int delay;
        final long expiresAt;
        final long deadlineNanos;
        final char[][] answers;
        AsyncAuthException async;
        ScheduledFuture<?> expiry;
        ScheduledFuture<?> decision;
        boolean responded;

        Attempt(String id, String scenario, int delay, char[][] answers) {
            this.id = id;
            this.scenario = scenario;
            this.delay = delay;
            this.answers = answers;
            expiresAt = Instant.now().getEpochSecond() + TTL_SECONDS;
            deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(TTL_SECONDS);
        }
    }

    FixtureServer() {
        scheduler.setRemoveOnCancelPolicy(true);
        scheduler.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        scheduler.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
    }

    static void privateDirectory(Path path) throws IOException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        }
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(path).equals(PosixFilePermissions.fromString("rwx------"))) {
            throw new IOException("Unsafe runtime directory");
        }
    }

    static void privateFile(Path path, String value) throws IOException {
        Path temporary = path.resolveSibling(path.getFileName() + ".new");
        Files.createFile(temporary,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(temporary, value, StandardCharsets.UTF_8, StandardOpenOption.WRITE);
        Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    static void deleteAttemptFiles(String id) throws IOException {
        Files.deleteIfExists(ROOT.resolve("attempts").resolve(id + ".json"));
        Files.deleteIfExists(ROOT.resolve("attempts").resolve(id + ".json.new"));
    }

    private String token() {
        byte[] bytes = new byte[12];
        random.nextBytes(bytes);
        return java.util.HexFormat.of().formatHex(bytes);
    }

    private char[] answer() {
        // Disposable answers only; not a user password or a deterministic credential.
        char[] value = new char[10];
        for (int i = 0; i < value.length; i++) {
            value[i] = (char) ('0' + random.nextInt(10));
        }
        return value;
    }

    static InteractiveChallenge challengeFor(String scenario, String id) {
        if (!SCENARIOS.contains(scenario)) {
            throw new IllegalArgumentException("Unknown fixture scenario");
        }
        InteractiveChallenge challenge = new InteractiveChallenge();
        challenge.setInteractionName("OpenLXSSH fixture " + id);
        challenge.setLanguageTag("en");
        challenge.setInteractionInstruction("Disposable test only; attempt " + id
                + (scenario.equals("two") ? "; enter the two independent test responses."
                : "; no input prompts. " + scenario + "; cancellation closes this connection."));
        if (scenario.equals("two")) {
            challenge.addPrompt("Test response A: ", false);
            challenge.addPrompt("Unclassified test response B: ", true);
        }
        // Intentionally NON-null with zero entries for zero/approval scenarios.
        // MINA emits one INFO_REQUEST; null would reject without emitting it.
        return challenge;
    }

    private String[] policy() throws IOException {
        Path file = ROOT.resolve("scenario");
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.size(file) > 128) {
            throw new IOException("Invalid scenario file");
        }
        String[] fields = Files.readString(file).strip().split(" ");
        if (fields.length != 2 || !SCENARIOS.contains(fields[0])) {
            throw new IOException("Invalid scenario");
        }
        int delay = Integer.parseInt(fields[1]);
        if (delay < 1 || delay > 60) {
            throw new IOException("Invalid delay");
        }
        return fields;
    }

    @Override
    public InteractiveChallenge generateChallenge(ServerSession session, String username, String lang, String subMethods)
            throws Exception {
        synchronized (lock) {
            Integer count = sessions.get(session);
            if (closed || !"fixture".equals(username) || count == null || count >= MAX_ATTEMPTS
                    || session.isClosing() || session.isAuthenticated()) {
                return null;
            }
            Attempt previous = pending.get(session);
            if (previous != null) {
                finishLocked(session, previous, "replaced");
            }
            if (pending.size() >= MAX_PENDING) {
                return null;
            }
            String[] policy = policy();
            String scenario = policy[0];
            Attempt attempt = new Attempt(token(), scenario, Integer.parseInt(policy[1]),
                    scenario.equals("two") ? new char[][] {answer(), answer()} : new char[0][]);
            sessions.put(session, count + 1);
            pending.put(session, attempt);
            generated++;
            try {
                if (attempt.answers.length != 0) {
                    privateFile(ROOT.resolve("attempts").resolve(attempt.id + ".json"),
                            "{\"attempt\":\"" + attempt.id + "\",\"expires_at\":" + attempt.expiresAt
                            + ",\"responses\":[\"" + new String(attempt.answers[0]) + "\",\""
                            + new String(attempt.answers[1]) + "\"],\"echo\":[false,true]}\n");
                }
                attempt.expiry = scheduler.schedule(() -> expire(session, attempt), TTL_SECONDS, TimeUnit.SECONDS);
                statusLocked();
                return challengeFor(scenario, attempt.id);
            } catch (Exception e) {
                finishLocked(session, attempt, "setup-failed");
                throw new IOException("Fixture challenge unavailable");
            }
        }
    }

    static boolean matches(char[][] expected, List<String> responses) {
        if (responses == null || expected.length != responses.size()) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < expected.length; i++) {
            String response = responses.get(i);
            if (response == null || response.length() != expected[i].length) {
                return false;
            }
            for (int j = 0; j < expected[i].length; j++) {
                difference |= expected[i][j] ^ response.charAt(j);
            }
        }
        return difference == 0;
    }

    @Override
    public boolean authenticate(ServerSession session, String username, List<String> responses) throws Exception {
        synchronized (lock) {
            Attempt attempt = pending.get(session);
            if (attempt == null || attempt.responded || !"fixture".equals(username)) {
                return false;
            }
            attempt.responded = true;
            responseCallbacks++;
            if (responses != null && responses.isEmpty()) {
                zeroResponseCallbacks++;
            }
            if (session.isClosing() || System.nanoTime() >= attempt.deadlineNanos
                    || !matches(attempt.answers, responses)) {
                finishLocked(session, attempt, "rejected");
                return false;
            }
            if (attempt.scenario.equals("two") || attempt.scenario.equals("zero-accept")) {
                finishLocked(session, attempt, "accepted");
                return true;
            }
            if (attempt.scenario.equals("zero-reject")) {
                finishLocked(session, attempt, "rejected");
                return false;
            }
            // A zero-response INFO_RESPONSE has reached this callback. Never sleep/wait here.
            attempt.async = new AsyncAuthException();
            if (!attempt.scenario.equals("timeout")) {
                attempt.decision = scheduler.schedule(
                        () -> decide(session, attempt, !attempt.scenario.equals("reject")),
                        attempt.delay, TimeUnit.SECONDS);
            }
            statusLocked();
            throw attempt.async;
        }
    }

    private void decide(ServerSession session, Attempt attempt, boolean approved) {
        AsyncAuthException result;
        synchronized (lock) {
            if (closed || pending.get(session) != attempt || session.isClosing() || session.isAuthenticated()
                    || System.nanoTime() >= attempt.deadlineNanos) {
                ignoredLateResults++;
                return;
            }
            result = attempt.async;
            finishQuietlyLocked(session, attempt, approved ? "approved" : "rejected");
        }
        // MINA calls the listener on this thread; NEVER hold the provider lock here.
        if (result != null) {
            result.setAuthed(approved);
        }
    }

    private void expire(ServerSession session, Attempt attempt) {
        AsyncAuthException result;
        synchronized (lock) {
            if (pending.get(session) != attempt) {
                return;
            }
            result = attempt.async;
            finishQuietlyLocked(session, attempt, "expired");
        }
        if (result != null && !session.isClosing()) {
            result.setAuthed(false);
        } else if (!session.isAuthenticated()) {
            session.close(true);
        }
    }

    private void finishLocked(ServerSession session, Attempt attempt, String reason) throws IOException {
        if (!pending.remove(session, attempt)) {
            return;
        }
        if (attempt.expiry != null) {
            attempt.expiry.cancel(false);
        }
        if (attempt.decision != null) {
            attempt.decision.cancel(false);
        }
        for (char[] answer : attempt.answers) {
            Arrays.fill(answer, '\0');
        }
        attempt.async = null;
        try {
            deleteAttemptFiles(attempt.id);
        } finally {
            outcomes.merge(reason, 1L, Long::sum);
        }
        statusLocked();
    }

    private void finishQuietlyLocked(ServerSession session, Attempt attempt, String reason) {
        try {
            finishLocked(session, attempt, reason);
        } catch (IOException e) {
            // Fail closed without an exception/response dump. No further authentication is allowed.
            closed = true;
            session.close(true);
        }
    }

    private void statusLocked() throws IOException {
        StringBuilder value = new StringBuilder("{\"generated\":" + generated
                + ",\"response_callbacks\":" + responseCallbacks + ",\"zero_response_callbacks\":"
                + zeroResponseCallbacks + ",\"ignored_late_results\":" + ignoredLateResults
                + ",\"sessions\":" + sessions.size() + ",\"scheduler_queue\":" + scheduler.getQueue().size()
                + ",\"pending\":[");
        boolean first = true;
        for (Attempt attempt : pending.values()) {
            if (!first) {
                value.append(',');
            }
            first = false;
            value.append("{\"attempt\":\"").append(attempt.id).append("\",\"scenario\":\"")
                    .append(attempt.scenario).append("\",\"prompt_count\":").append(attempt.answers.length)
                    .append(",\"responded\":").append(attempt.responded).append(",\"expires_at\":")
                    .append(attempt.expiresAt).append('}');
        }
        value.append("],\"outcomes\":{");
        first = true;
        for (Map.Entry<String, Long> item : outcomes.entrySet()) {
            if (!first) {
                value.append(',');
            }
            first = false;
            value.append('"').append(item.getKey()).append("\":").append(item.getValue());
        }
        privateFile(ROOT.resolve("status.json"), value.append("}}\n").toString());
    }

    @Override
    public void sessionCreated(Session session) {
        synchronized (lock) {
            if (closed || sessions.size() >= MAX_SESSIONS) {
                session.close(true);
                return;
            }
            sessions.put(session, 0);
        }
    }

    @Override
    public void sessionClosed(Session session) {
        synchronized (lock) {
            Attempt attempt = pending.get(session);
            if (attempt != null) {
                finishQuietlyLocked((ServerSession) session, attempt, "session-closed");
            }
            sessions.remove(session);
            try {
                statusLocked();
            } catch (IOException e) {
                closed = true;
            }
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            closed = true;
            for (Map.Entry<ServerSession, Attempt> entry : new IdentityHashMap<>(pending).entrySet()) {
                finishQuietlyLocked(entry.getKey(), entry.getValue(), "shutdown");
            }
        }
        scheduler.shutdownNow();
    }

    /** A fixed success marker, not a local shell or remote command executor. */
    static final class SuccessCommand implements Command {
        private OutputStream output;
        private ExitCallback exit;
        @Override public void setInputStream(InputStream input) { }
        @Override public void setOutputStream(OutputStream value) { output = value; }
        @Override public void setErrorStream(OutputStream error) { }
        @Override public void setExitCallback(ExitCallback value) { exit = value; }
        @Override public void start(ChannelSession channel, Environment env) throws IOException {
            output.write("OpenLXSSH fixture authentication succeeded.\r\n".getBytes(StandardCharsets.UTF_8));
            output.flush();
            exit.onExit(0);
        }
        @Override public void destroy(ChannelSession channel) { }
    }

    static void serve() throws Exception {
        privateDirectory(ROOT);
        Path attempts = ROOT.resolve("attempts");
        privateDirectory(attempts);
        // Runtime tmpfs is dedicated. Refuse stale state rather than adopt credentials/trust.
        try (Stream<Path> existing = Files.list(attempts)) {
            if (existing.findAny().isPresent() || Files.exists(ROOT.resolve("trust.json"))) {
                throw new IOException("Refusing stale runtime; recreate the owned container");
            }
        }
        privateFile(ROOT.resolve("scenario"), "two 8\n");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        KeyPair hostKey = generator.generateKeyPair();
        privateFile(ROOT.resolve("trust.json"), "{\"known_hosts\":\"[127.0.0.1]:22225 "
                + PublicKeyEntry.toString(hostKey.getPublic()) + "\\n\",\"fingerprint\":\""
                + KeyUtils.getFingerPrint(hostKey.getPublic()) + "\"}\n");
        try (FixtureServer fixture = new FixtureServer(); SshServer server = SshServer.setUpDefaultServer()) {
            server.setHost("0.0.0.0"); // Container namespace only; Compose publishes host LOOPBACK only.
            server.setPort(2222);
            server.setIoServiceFactoryFactory(new Nio2ServiceFactoryFactory());
            server.setKeyPairProvider(KeyPairProvider.wrap(hostKey));
            server.setUserAuthFactories(List.of(UserAuthKeyboardInteractiveFactory.INSTANCE));
            server.setKeyboardInteractiveAuthenticator(fixture);
            server.addSessionListener(fixture);
            server.setForwardingFilter(RejectAllForwardingFilter.INSTANCE);
            server.setShellFactory(channel -> new SuccessCommand());
            server.setCommandFactory((channel, command) -> {
                if (!"fixture-ok".equals(command)) {
                    throw new IOException("Only fixture-ok is available");
                }
                return new SuccessCommand();
            });
            server.setSubsystemFactories(List.of());
            CoreModuleProperties.AUTH_TIMEOUT.set(server, Duration.ofSeconds(AUTH_SECONDS));
            CoreModuleProperties.IDLE_TIMEOUT.set(server, Duration.ofSeconds(120));
            CoreModuleProperties.MAX_AUTH_REQUESTS.set(server, MAX_ATTEMPTS);
            CoreModuleProperties.MAX_CONCURRENT_SESSIONS.set(server, MAX_SESSIONS);
            CoreModuleProperties.MAX_CONCURRENT_CHANNELS.set(server, 1);
            CoreModuleProperties.NIO_WORKERS.set(server, 2);
            fixture.statusLocked();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                fixture.close();
                server.close(true);
            }, "fixture-shutdown"));
            server.start();
            privateFile(ROOT.resolve("ready"), "ready\n");
            new CountDownLatch(1).await();
        }
    }

    public static void main(String[] args) {
        try {
            if (!Arrays.equals(args, new String[] {"serve", "--authorized-run"})) {
                throw new IllegalArgumentException("Explicit authorized container serve only");
            }
            serve();
        } catch (Exception e) {
            // Never print exceptions, packet data, response text or session objects.
            System.err.println("Fixture stopped or refused; inspect private metadata and reviewed configuration.");
            System.exit(1);
        }
    }
}
