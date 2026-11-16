// Detects Vercel preview websites that have Deployment Protection enabled.
//
// This file is loaded by .github/workflows/pr.yml from the default branch. It must never
// read or execute anything from the PR head: the only PR-controlled inputs are the list of
// changed filenames and the PR description, both of which are treated as untrusted text.

const COMMENT_MARKER = "<!-- is-a-dev-bot: vercel-deployment-protection -->";

const PREVIEW_START = "<!-- WEBSITE_PREVIEW_START -->";
const PREVIEW_END = "<!-- WEBSITE_PREVIEW_END -->";

const DOMAIN_FILE_REGEX = /^domains\/[^/]+\.json$/;
const PREVIEW_HOST_SUFFIX = ".vercel.app";

// A protected deployment answers with a redirect to Vercel's SSO flow. The first hop is
// /sso-api, the browser later lands on /sso/access/request.
const PROTECTION_HOST = "vercel.com";
const PROTECTION_PATHS = ["/sso-api", "/sso/access/request"];

const MAX_CHECKED_URLS = 3;
const REQUEST_TIMEOUT_MS = 10000;

const MEDIA_PATH = "media/vercel-deployment-protection";

function countOccurrences(text, needle) {
    return text.split(needle).length - 1;
}

/**
 * Whether the PR adds or modifies (but does not delete) a domains/<name>.json file. This
 * includes Vercel verification files (domains/_vercel.<name>.json).
 * `files` is the response of the "list pull request files" API.
 */
function touchesDomainFile(files) {
    return files.some((file) => file.status !== "removed" && DOMAIN_FILE_REGEX.test(file.filename));
}

/**
 * Returns the set of distinct links found between the website preview markers.
 */
function extractPreviewLinks(body) {
    const text = typeof body === "string" ? body : "";

    if (countOccurrences(text, PREVIEW_START) !== 1 || countOccurrences(text, PREVIEW_END) !== 1) {
        return { links: [], error: "The website preview markers are missing or duplicated." };
    }

    const start = text.indexOf(PREVIEW_START) + PREVIEW_START.length;
    const end = text.indexOf(PREVIEW_END);

    if (end < start) {
        return { links: [], error: "The website preview markers are out of order." };
    }

    const section = text.slice(start, end).replace(/<!--[\s\S]*?-->/g, " ");
    const matches = section.match(/https?:\/\/[^\s<>()[\]"'`]+/gi) || [];
    const links = new Set();

    for (const match of matches) {
        links.add(match.replace(/[.,;:!?*_~]+$/, ""));
    }

    return { links: [...links], error: null };
}

/**
 * Only HTTPS URLs on a subdomain of vercel.app, on the default port and without
 * credentials, may be requested.
 */
function validatePreviewUrl(link) {
    let url;

    try {
        url = new URL(link);
    } catch {
        return { ok: false, reason: "it is not a valid URL" };
    }

    if (url.protocol !== "https:") {
        return { ok: false, reason: "it does not use HTTPS" };
    }

    if (url.username || url.password) {
        return { ok: false, reason: "it contains credentials" };
    }

    if (url.port) {
        return { ok: false, reason: "it uses a custom port" };
    }

    // `hostname` is already lowercased. Requiring the leading dot of the suffix and at least
    // one label before it rejects vercel.app.attacker.example, evilvercel.app, vercel.app
    // itself and trailing-dot hostnames.
    if (!url.hostname.endsWith(PREVIEW_HOST_SUFFIX) || url.hostname.length === PREVIEW_HOST_SUFFIX.length) {
        return { ok: false, reason: "its hostname is not a subdomain of vercel.app" };
    }

    // The hostname is echoed in a comment, so it may only contain plain DNS characters
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(url.hostname)) {
        return { ok: false, reason: "its hostname contains unexpected characters" };
    }

    return { ok: true, url };
}

/**
 * Classifies a response that was fetched without following redirects.
 *
 * - A redirect to Vercel's SSO pages means the deployment is protected.
 * - A successful response, or a redirect to anywhere outside of vercel.com (for example
 *   to /en or to a custom domain), means there is no login protection in front of it.
 * - Everything else (errors, other vercel.com redirects) is inconclusive.
 */
function classifyResponse(status, location, requestUrl) {
    if (status >= 300 && status < 400 && location) {
        let target;

        try {
            target = new URL(location, requestUrl);
        } catch {
            return "inconclusive";
        }

        if (
            target.protocol === "https:" &&
            target.hostname === PROTECTION_HOST &&
            PROTECTION_PATHS.includes(target.pathname)
        ) {
            return "protected";
        }

        if (target.hostname === PROTECTION_HOST || target.hostname.endsWith(`.${PROTECTION_HOST}`)) {
            return "inconclusive";
        }

        return "accessible";
    }

    if (status >= 200 && status < 300) {
        return "accessible";
    }

    return "inconclusive";
}

/**
 * Makes a single bounded HEAD request. Redirects are not followed and no body is read.
 * Timeouts and network failures are inconclusive.
 */
async function checkUrl(url, fetchImpl = fetch) {
    try {
        const response = await fetchImpl(url.href, {
            method: "HEAD",
            redirect: "manual",
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
        });

        return {
            result: classifyResponse(response.status, response.headers.get("location"), url.href),
            detail: `HTTP ${response.status}`
        };
    } catch (error) {
        return { result: "inconclusive", detail: `request failed (${error.name})` };
    }
}

/**
 * Runs the whole check.
 *
 * Outcomes:
 * - "not-applicable": no domain file is added or modified, or there is no eligible preview link.
 * - "protected": at least one preview link redirects to Vercel's login protection.
 * - "accessible": every eligible preview website responded without login protection.
 * - "inconclusive": anything else.
 *
 * `protectedSites` only contains origins (https://<hostname>) so that it is safe to
 * include in a comment.
 */
async function runCheck({ files, body, fetchImpl }) {
    const notes = [];

    if (!touchesDomainFile(files)) {
        notes.push("No domains/<name>.json file is added or modified, nothing to check.");
        return { outcome: "not-applicable", protectedSites: [], notes };
    }

    const { links, error } = extractPreviewLinks(body);

    if (error) {
        notes.push(error);
        return { outcome: "inconclusive", protectedSites: [], notes };
    }

    const eligible = new Map();

    for (const link of links) {
        const validation = validatePreviewUrl(link);

        if (validation.ok) {
            // Protection applies to a whole deployment, so each website is only checked once
            if (!eligible.has(validation.url.origin)) {
                eligible.set(validation.url.origin, validation.url);
            }
        } else {
            notes.push(`Skipped ${JSON.stringify(link)} because ${validation.reason}.`);
        }
    }

    if (eligible.size === 0) {
        notes.push("No HTTPS *.vercel.app link was found in the website preview section.");
        return { outcome: "not-applicable", protectedSites: [], notes };
    }

    const urls = [...eligible.values()];
    const checked = urls.slice(0, MAX_CHECKED_URLS);

    if (urls.length > checked.length) {
        notes.push(`Found ${urls.length} eligible websites, only the first ${checked.length} were checked.`);
    }

    const protectedSites = new Set();
    let allAccessible = urls.length === checked.length;

    for (const url of checked) {
        const { result, detail } = await checkUrl(url, fetchImpl);

        notes.push(`${url.origin}: ${result} (${detail})`);

        if (result === "protected") {
            protectedSites.add(url.origin);
        }

        if (result !== "accessible") {
            allAccessible = false;
        }
    }

    if (protectedSites.size > 0) {
        return { outcome: "protected", protectedSites: [...protectedSites], notes };
    }

    return { outcome: allAccessible ? "accessible" : "inconclusive", protectedSites: [], notes };
}

/**
 * `repository` (owner/name) and `branch` say where the screenshots are hosted. The workflow
 * passes the repository it runs in and its default branch, so the images also load on forks.
 */
function buildComment(protectedSites, { repository = "is-a-dev/register", branch = "main" } = {}) {
    const mediaBase = `https://raw.githubusercontent.com/${repository}/${encodeURIComponent(branch)}/${MEDIA_PATH}`;

    return [
        COMMENT_MARKER,
        "## ⚠️ Website preview requires a Vercel login",
        "",
        "Your website preview redirects to a Vercel login page, so reviewers cannot view it:",
        "",
        ...protectedSites.map((site) => `- ${site}`),
        "",
        "> [!TIP]",
        "> You can verify if your site is publicly accessible by opening the link in an **Incognito / Guest window** in your browser.",
        "",
        "### How to fix: Turn off Vercel Deployment Protection",
        "",
        "Vercel enables login protection by default for preview deployments. To disable it:",
        "",
        "1. Open your project dashboard on **Vercel**.",
        "2. Navigate to **Settings** > **Deployment Protection**.",
        "3. Toggle off **Vercel Authentication** (Require Login) and click **Save**.",
        "4. Test your link in an Incognito window to confirm it loads without a login prompt.",
        "",
        "<table>",
        "  <tr>",
        '    <td align="center">',
        `      <img width="299" alt="Vercel project settings" src="${mediaBase}/step-1-settings.png" />`,
        "      <br><br>",
        "      <b>Step 1: Go to your project Settings</b>",
        "    </td>",
        '    <td align="center">',
        `      <img width="292" alt="Vercel Deployment Protection menu" src="${mediaBase}/step-2-deployment-protection.png" />`,
        "      <br><br>",
        "      <b>Step 2: Select Deployment Protection</b>",
        "    </td>",
        "  </tr>",
        "</table>",
        "",
        `<img width="1080" alt="Toggle off Require Login" src="${mediaBase}/step-3-disable-require-login.png" />`,
        "<br><br>",
        '<b>Step 3: Turn off "Require Login" and save changes</b>',
        "",
        "---",
        "Once fixed, edit your PR description to run this check again."
    ].join("\n");
}

module.exports = {
    COMMENT_MARKER,
    buildComment,
    checkUrl,
    classifyResponse,
    extractPreviewLinks,
    runCheck,
    touchesDomainFile,
    validatePreviewUrl
};
