import t from "ava";

import checker from "../util/check-vercel-protection.cjs";

const { buildComment, classifyResponse, extractPreviewLinks, runCheck, touchesVercelFile, validatePreviewUrl } =
    checker;

const START = "<!-- WEBSITE_PREVIEW_START -->";
const END = "<!-- WEBSITE_PREVIEW_END -->";

const SSO_REDIRECT = "https://vercel.com/sso-api?url=https%3A%2F%2Fabc.vercel.app%2F&nonce=123";

function body(preview) {
    return `# Website Preview\n\n${START}\n${preview}\n${END}\n\n# Website Purpose`;
}

function fakeFetch(responses, calls = []) {
    return async (href, options) => {
        calls.push({ href, options });

        const response = responses[href];

        if (!response) throw new TypeError("fetch failed");

        return {
            status: response.status,
            headers: { get: (name) => (name === "location" ? (response.location ?? null) : null) }
        };
    };
}

const vercelFile = [{ filename: "domains/_vercel.abc.json", status: "added" }];

t("Vercel protection check only applies to non-deleted _vercel files", (t) => {
    t.true(touchesVercelFile([{ filename: "domains/_vercel.abc.json", status: "added" }]));
    t.true(touchesVercelFile([{ filename: "domains/_vercel.abc.json", status: "modified" }]));
    t.false(touchesVercelFile([{ filename: "domains/_vercel.abc.json", status: "removed" }]));
    t.false(touchesVercelFile([{ filename: "domains/abc.json", status: "added" }]));
    t.false(touchesVercelFile([{ filename: "domains/_vercel.json", status: "added" }]));
    t.false(touchesVercelFile([{ filename: "domains/_vercel.a.b.json", status: "added" }]));
    t.false(touchesVercelFile([{ filename: "other/domains/_vercel.abc.json", status: "added" }]));
    t.false(touchesVercelFile([]));
});

t("Vercel protection check extracts the set of links between the preview markers", (t) => {
    t.deepEqual(extractPreviewLinks(body("https://abc.vercel.app/")).links, ["https://abc.vercel.app/"]);

    t.deepEqual(
        extractPreviewLinks(
            body("[site](https://abc.vercel.app), https://abc.vercel.app and <https://github.com/abc>.")
        ).links,
        ["https://abc.vercel.app", "https://github.com/abc"]
    );

    // Links outside of the markers and inside of HTML comments are ignored
    t.deepEqual(
        extractPreviewLinks(`https://outside.vercel.app ${START} <!-- https://hidden.vercel.app --> ${END}`).links,
        []
    );

    t.deepEqual(extractPreviewLinks(body("abc.vercel.app")).links, []);
});

t("Vercel protection check handles missing or malformed preview markers", (t) => {
    for (const value of [
        null,
        undefined,
        "",
        "https://abc.vercel.app",
        `${START} https://abc.vercel.app`,
        `${END} https://abc.vercel.app ${START}`,
        `${START} https://a.vercel.app ${END} ${START} https://b.vercel.app ${END}`
    ]) {
        const { links, error } = extractPreviewLinks(value);

        t.deepEqual(links, []);
        t.truthy(error);
    }
});

t("Vercel protection check only allows HTTPS *.vercel.app URLs", (t) => {
    for (const link of [
        "https://abc.vercel.app",
        "https://abc.vercel.app/path?query=1",
        "https://ABC.Vercel.App/",
        "https://a-b-c-projects.vercel.app:443/"
    ]) {
        t.true(validatePreviewUrl(link).ok, link);
    }

    for (const link of [
        "http://abc.vercel.app",
        "https://vercel.app",
        "https://.vercel.app",
        "https://evilvercel.app",
        "https://abc.vercel.app.attacker.example",
        "https://attacker.example/abc.vercel.app",
        "https://attacker.example#.vercel.app",
        "https://attacker.example?.vercel.app",
        "https://abc.vercel.app@attacker.example",
        "https://user:pass@abc.vercel.app",
        "https://abc.vercel.app:8443",
        "https://abc.vercel.app.",
        "https://abc.vercel.com",
        "https://",
        "not a url"
    ]) {
        t.false(validatePreviewUrl(link).ok, link);
    }
});

t("Vercel protection check only detects redirects to the Vercel SSO pages", (t) => {
    const url = "https://abc.vercel.app/";

    t.is(classifyResponse(302, SSO_REDIRECT, url), "protected");
    t.is(classifyResponse(307, "https://vercel.com/sso/access/request?next=abc", url), "protected");

    t.is(classifyResponse(200, null, url), "accessible");
    t.is(classifyResponse(204, null, url), "accessible");

    t.is(classifyResponse(302, "https://vercel.com/login", url), "inconclusive");
    t.is(classifyResponse(302, "https://vercel.com/sso-api/other", url), "inconclusive");
    t.is(classifyResponse(302, "http://vercel.com/sso-api", url), "inconclusive");
    t.is(classifyResponse(302, "https://vercel.com.attacker.example/sso-api", url), "inconclusive");
    t.is(classifyResponse(302, "https://attacker.example/sso/access/request", url), "inconclusive");
    t.is(classifyResponse(302, "/sso-api", url), "inconclusive");
    t.is(classifyResponse(302, "https://", url), "inconclusive");
    t.is(classifyResponse(302, null, url), "inconclusive");
    t.is(classifyResponse(200, SSO_REDIRECT, url), "accessible");
    t.is(classifyResponse(401, null, url), "inconclusive");
    t.is(classifyResponse(404, null, url), "inconclusive");
    t.is(classifyResponse(500, null, url), "inconclusive");
});

t("Vercel protection check makes no requests when it does not apply", async (t) => {
    const calls = [];
    const fetchImpl = fakeFetch({}, calls);

    const noFile = await runCheck({
        files: [{ filename: "domains/abc.json", status: "added" }],
        body: body("https://abc.vercel.app"),
        fetchImpl
    });

    const deleted = await runCheck({
        files: [{ filename: "domains/_vercel.abc.json", status: "removed" }],
        body: body("https://abc.vercel.app"),
        fetchImpl
    });

    const otherHost = await runCheck({
        files: vercelFile,
        body: body("https://abc.github.io and https://abc.vercel.app.attacker.example"),
        fetchImpl
    });

    const malformed = await runCheck({ files: vercelFile, body: "https://abc.vercel.app", fetchImpl });

    t.is(noFile.outcome, "not-applicable");
    t.is(deleted.outcome, "not-applicable");
    t.is(otherHost.outcome, "not-applicable");
    t.is(malformed.outcome, "inconclusive");
    t.is(calls.length, 0);
});

t("Vercel protection check reports protected and accessible previews", async (t) => {
    const calls = [];

    const isProtected = await runCheck({
        files: vercelFile,
        body: body("https://abc.vercel.app/some/path?x=y"),
        fetchImpl: fakeFetch({ "https://abc.vercel.app/some/path?x=y": { status: 302, location: SSO_REDIRECT } }, calls)
    });

    t.is(isProtected.outcome, "protected");
    t.deepEqual(isProtected.protectedSites, ["https://abc.vercel.app"]);

    t.is(calls.length, 1);
    t.is(calls[0].options.method, "HEAD");
    t.is(calls[0].options.redirect, "manual");
    t.truthy(calls[0].options.signal);

    const accessible = await runCheck({
        files: vercelFile,
        body: body("https://abc.vercel.app"),
        fetchImpl: fakeFetch({ "https://abc.vercel.app/": { status: 200 } })
    });

    t.is(accessible.outcome, "accessible");
    t.deepEqual(accessible.protectedSites, []);
});

t("Vercel protection check treats failures as inconclusive", async (t) => {
    const networkError = await runCheck({
        files: vercelFile,
        body: body("https://abc.vercel.app"),
        fetchImpl: fakeFetch({})
    });

    const notFound = await runCheck({
        files: vercelFile,
        body: body("https://abc.vercel.app"),
        fetchImpl: fakeFetch({ "https://abc.vercel.app/": { status: 404 } })
    });

    const mixed = await runCheck({
        files: vercelFile,
        body: body("https://abc.vercel.app https://def.vercel.app"),
        fetchImpl: fakeFetch({ "https://abc.vercel.app/": { status: 200 } })
    });

    t.is(networkError.outcome, "inconclusive");
    t.is(notFound.outcome, "inconclusive");
    t.is(mixed.outcome, "inconclusive");
});

t("Vercel protection check handles multiple preview links", async (t) => {
    const anyProtected = await runCheck({
        files: vercelFile,
        body: body("https://abc.vercel.app https://def.vercel.app https://github.com/abc"),
        fetchImpl: fakeFetch({
            "https://abc.vercel.app/": { status: 200 },
            "https://def.vercel.app/": { status: 302, location: SSO_REDIRECT }
        })
    });

    t.is(anyProtected.outcome, "protected");
    t.deepEqual(anyProtected.protectedSites, ["https://def.vercel.app"]);

    // No more than 3 links are requested, so more accessible links than that are inconclusive
    const calls = [];
    const responses = {};
    const links = ["a", "b", "c", "d", "e"].map((name) => `https://${name}.vercel.app/`);

    for (const link of links) responses[link] = { status: 200 };

    const tooMany = await runCheck({
        files: vercelFile,
        body: body(links.join("\n")),
        fetchImpl: fakeFetch(responses, calls)
    });

    t.is(tooMany.outcome, "inconclusive");
    t.is(calls.length, 3);
});

t("Vercel protection comment contains the marker and the protected sites", (t) => {
    const comment = buildComment(["https://abc.vercel.app"]);

    t.true(comment.startsWith(checker.COMMENT_MARKER));
    t.true(comment.includes("- https://abc.vercel.app"));
});
