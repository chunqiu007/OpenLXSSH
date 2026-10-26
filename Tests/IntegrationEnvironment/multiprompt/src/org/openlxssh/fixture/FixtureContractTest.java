package org.openlxssh.fixture;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.keyboard.InteractiveChallenge;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;

/** Real-library contract checks, NOT network/wire interoperability acceptance. Container Java only. */
public final class FixtureContractTest {
    private static void check(boolean value, String message) {
        if (!value) {
            throw new AssertionError(message);
        }
    }

    private static void inspect(String scenario, int expected) {
        InteractiveChallenge challenge = FixtureServer.challengeFor(scenario, "nonsecret-contract-id");
        check(challenge != null, "zero challenge must not mean null/reject");
        check(challenge.getPrompts().size() == expected, "prompt count");
        ByteArrayBuffer buffer = new ByteArrayBuffer();
        challenge.append(buffer);
        check(buffer.getString().contains("nonsecret-contract-id"), "non-secret attempt metadata");
        buffer.getString();
        buffer.getString();
        check(buffer.getInt() == expected, "real MINA serialization count");
        if (expected == 2) {
            check(buffer.getString().equals("Test response A: "), "first prompt/order");
            check(!buffer.getBoolean(), "first echo false");
            check(buffer.getString().equals("Unclassified test response B: "), "second prompt/order");
            check(buffer.getBoolean(), "second echo true");
        }
        check(buffer.available() == 0, "single serialized challenge, no extra messages");
    }

    public static void main(String[] args) throws Exception {
        inspect("two", 2);
        for (String scenario : FixtureServer.SCENARIOS) {
            if (!scenario.equals("two")) {
                inspect(scenario, 0);
            }
        }
        check(KeyboardInteractiveAuthenticator.NONE.generateChallenge(null, null, null, null) == null,
                "upstream null path is rejection, not a zero challenge");
        check(FixtureServer.matches(new char[0][], List.of()), "zero response count accepted");
        check(!FixtureServer.matches(new char[0][], List.of("not-a-secret")), "wrong zero response count");
        char[][] values = {"public-a".toCharArray(), "public-b".toCharArray()};
        check(FixtureServer.matches(values, List.of("public-a", "public-b")), "ordered answers");
        check(!FixtureServer.matches(values, List.of("public-b", "public-a")), "swapped answers rejected");
        check(!FixtureServer.matches(values, List.of("public-a")), "count mismatch rejected");
        check(!FixtureServer.matches(values, List.of("public-a", "public-x")), "wrong answer rejected");
        AtomicInteger completions = new AtomicInteger();
        AsyncAuthException async = new AsyncAuthException();
        async.addListener(accepted -> completions.addAndGet(accepted ? 1 : 100));
        async.setAuthed(true);
        async.setAuthed(false);
        check(completions.get() == 1, "upstream completion is one-shot");
        System.out.println("Real-library serialization/validation contracts passed; no wire connection performed.");
    }
}
