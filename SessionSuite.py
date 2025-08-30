# SessionSuite (advanced + behavioral LOGOUT)
# Jython 2.7.x, Burp Extender API
#
# Features:
# - Tracker: cookies, bearer tokens, JWTs (request/response, hashed ids)
# - Security Analyzer: cookie flags (Secure/HttpOnly/SameSite), deep JWT checks
# - Auth Flow: LOGIN / REFRESH / LOGOUT (endpoint + behavioral) + 401/403
# - Consistency Checker: generate Repeater tests (no-cookie, no-auth, invalid bearer,
#   corrupt JWT, replay last bearer, expired JWT)
# - Rotation/fixation: flag same session across login; non-rotating JWT on refresh
# - Multiple-session awareness: repeated token sightings
# - Export: CSV/JSON for Tracker and Analyzer; DOT export for flow
#
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from java.util import ArrayList
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JButton, JLabel,
                         JCheckBox, BoxLayout, Box, JMenuItem, JOptionPane, JFileChooser,
                         JTextArea, SwingUtilities)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension
import time, re, json, hashlib, base64

# ---------- utils ----------

def now_ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def sha1_short(s):
    try:
        h = hashlib.sha1(s).hexdigest()
    except:
        h = hashlib.sha1(s.encode('utf-8')).hexdigest()
    return h[:10]

def b64url_decode(s):
    s = s.replace('-', '+').replace('_', '/')
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    return base64.b64decode(s)

def b64url_encode(b):
    s = base64.b64encode(b)
    s = s.replace('+', '-').replace('/', '_')
    return s.replace('=', '')

JWT_RE = re.compile(r'eyJ[0-9A-Za-z_-]*\.[0-9A-Za-z_-]*\.[0-9A-Za-z_-]*')
SESSION_COOKIE_HINTS = re.compile(r'(session|sess|sid|jsessionid|phpsessid|auth|token)', re.I)
LOGIN_HINTS   = re.compile(r'login|signin|auth', re.I)
REFRESH_HINTS = re.compile(r'refresh|token', re.I)
# Expanded to catch more server-side logout patterns
LOGOUT_HINTS  = re.compile(r'logout|signout|revoke|invalidate|session(s)?/?(terminate|destroy)?', re.I)

def try_decode_jwt(jwt_str):
    try:
        parts = jwt_str.split('.')
        if len(parts) < 2:
            return None, None
        hdr = json.loads(b64url_decode(parts[0]))
        pl  = json.loads(b64url_decode(parts[1]))
        return hdr, pl
    except:
        return None, None

def parse_cookies_from_header(cookie_header_val):
    items = []
    if not cookie_header_val:
        return items
    for p in cookie_header_val.split(';'):
        if '=' in p:
            name, val = p.strip().split('=', 1)
            items.append((name.strip(), val.strip()))
    return items

def parse_set_cookie_lines(resp_headers):
    out = []
    for h in resp_headers:
        if h.lower().startswith('set-cookie:'):
            line = h.split(':',1)[1].strip()
            parts = [x.strip() for x in line.split(';')]
            if not parts:
                continue
            if '=' in parts[0]:
                name, val = parts[0].split('=',1)
            else:
                name, val = parts[0], ''
            attrs = {}
            for a in parts[1:]:
                if '=' in a:
                    k,v = a.split('=',1); attrs[k.lower()] = v
                else:
                    attrs[a.lower()] = True
            out.append({'name':name, 'value':val, 'attrs':attrs})
    return out

def cookie_issue_flags(attrs):
    issues = []
    if 'secure' not in attrs:   issues.append('Cookie missing Secure')
    if 'httponly' not in attrs: issues.append('Cookie missing HttpOnly')
    if 'samesite' not in attrs: issues.append('Cookie missing SameSite')
    return issues

def is_in_scope(callbacks, url):
    try:
        return callbacks.isInScope(url)
    except:
        return True

# ---------- advanced checks ----------

MAX_JWT_LIFETIME_SECONDS = 60*60*24*7   # 7 days
OLD_IAT_SECONDS          = 60*60*24*30  # 30 days

def jwt_deep_issues(header, payload, now_epoch):
    issues = []
    if header is None or payload is None:
        return ['JWT unparsable']
    alg = header.get('alg')
    if not alg:
        issues.append('JWT header missing alg')
    elif str(alg).lower() == 'none':
        issues.append('JWT alg "none"')
    exp = payload.get('exp'); nbf = payload.get('nbf'); iat = payload.get('iat')

    # exp checks
    if exp is None:
        issues.append('JWT missing exp')
    else:
        try:
            expf = float(exp)
            if now_epoch > expf:
                issues.append('JWT expired')
            if iat is not None:
                try:
                    iatf = float(iat)
                    if expf - iatf > MAX_JWT_LIFETIME_SECONDS:
                        issues.append('JWT lifetime too long (>7d)')
                except:
                    pass
        except:
            issues.append('JWT exp not numeric')

    # iat checks
    if iat is not None:
        try:
            if now_epoch - float(iat) > OLD_IAT_SECONDS:
                issues.append('JWT iat very old (>30d)')
        except:
            issues.append('JWT iat not numeric')

    # nbf in future
    if nbf is not None:
        try:
            if float(nbf) > now_epoch + 15:  # allow small skew
                issues.append('JWT nbf in the future')
        except:
            issues.append('JWT nbf not numeric')

    return issues

def synthesize_expired_jwt(jwt_str):
    """Set payload.exp to (now-1h) without fixing signature (server should reject)."""
    try:
        parts = jwt_str.split('.')
        hdr = json.loads(b64url_decode(parts[0]))
        pl  = json.loads(b64url_decode(parts[1]))
        pl['exp'] = int(time.time()) - 3600
        new_pl = b64url_encode(json.dumps(pl).encode('utf-8'))
        parts[1] = new_pl
        return '.'.join(parts)
    except:
        return jwt_str + 'A'

# ---------- core extension ----------

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.cb = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SessionSuite (advanced)")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        # Data stores
        self.tokens = []           # tracker rows
        self.token_seen = set()    # dedupe
        self.issues = []           # analyzer rows
        self.timeline = []         # flow events

        # State for fixation/rotation/replay/behavioral logout
        self.last_cookie_id_by_host   = {}  # host -> last seen session cookie hash (pre-login)
        self.last_jwt_id_by_host      = {}  # host -> last seen jwt hash
        self.last_bearer_raw_by_host  = {}  # host -> last raw bearer for replay
        self.concurrent_counter        = {}  # (host, ttype, name, tid) -> count
        self.had_auth_recent           = {}  # host -> epoch of last request with Authorization
        self.authless_streak           = {}  # host -> consecutive requests without Authorization

        # UI
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.printOutput("[SessionSuite] init complete")

    # ---------- UI ----------

    def _build_ui(self):
        self.tabs = JTabbedPane()

        # Tracker
        self.trackerModel = DefaultTableModel(['time','host','type','name','id','where','url'], 0)
        self.trackerTable = JTable(self.trackerModel)
        bar1 = JPanel()
        btnExpCSV1  = JButton("Export CSV",  actionPerformed=lambda e: self._export_table_csv(self.trackerModel))
        btnExpJSON1 = JButton("Export JSON", actionPerformed=lambda e: self._export_table_json(self.trackerModel))
        bar1.add(btnExpCSV1); bar1.add(btnExpJSON1)
        p1 = JPanel(BorderLayout()); p1.add(JScrollPane(self.trackerTable), BorderLayout.CENTER); p1.add(bar1, BorderLayout.SOUTH)

        # Consistency Checker options
        p2 = JPanel(); p2.setLayout(BoxLayout(p2, BoxLayout.Y_AXIS))
        p2.add(JLabel("Right-click a request → SessionSuite → Generate tests"))
        self.ccStripCookies = JCheckBox("Test: strip Cookie", True)
        self.ccStripAuth    = JCheckBox("Test: strip Authorization", True)
        self.ccInvalidBearer= JCheckBox("Test: invalid Bearer", True)
        self.ccCorruptJWT   = JCheckBox("Test: corrupt JWT", True)
        self.ccReplayLast   = JCheckBox("Test: replay last seen bearer", True)
        self.ccExpiredJWT   = JCheckBox("Test: expired JWT (exp in the past)", True)
        for w in [self.ccStripCookies, self.ccStripAuth, self.ccInvalidBearer, self.ccCorruptJWT, self.ccReplayLast, self.ccExpiredJWT]:
            p2.add(w)

        # Auth Flow
        self.timelineArea = JTextArea(12, 80); self.timelineArea.setEditable(False)
        btnExportDOT = JButton("Export DOT...", actionPerformed=self._export_dot)
        p3 = JPanel(BorderLayout()); p3.add(JScrollPane(self.timelineArea), BorderLayout.CENTER); p3.add(btnExportDOT, BorderLayout.SOUTH)

        # Analyzer
        self.issuesModel = DefaultTableModel(['time','host','type','description','evidence','url'], 0)
        self.issuesTable = JTable(self.issuesModel)
        bar4 = JPanel()
        btnExpCSV4  = JButton("Export CSV",  actionPerformed=lambda e: self._export_table_csv(self.issuesModel))
        btnExpJSON4 = JButton("Export JSON", actionPerformed=lambda e: self._export_table_json(self.issuesModel))
        bar4.add(btnExpCSV4); bar4.add(btnExpJSON4)
        p4 = JPanel(BorderLayout()); p4.add(JScrollPane(self.issuesTable), BorderLayout.CENTER); p4.add(bar4, BorderLayout.SOUTH)

        self.tabs.addTab("Tracker", p1)
        self.tabs.addTab("Consistency Checker", p2)
        self.tabs.addTab("Auth Flow", p3)
        self.tabs.addTab("Security Analyzer", p4)

        self.root = JPanel(BorderLayout()); self.root.add(self.tabs, BorderLayout.CENTER)

    def getTabCaption(self):
        return "SessionSuite"

    def getUiComponent(self):
        return self.root

    # ---------- HTTP listener ----------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                self._handle_request(messageInfo)
            else:
                self._handle_response(messageInfo)
        except Exception as e:
            self.cb.printError("[SessionSuite] error: %s" % e)

    def _service_host(self, svc):
        try:
            return svc.getHost()
        except:
            return 'unknown'

    def _handle_request(self, mi):
        req = mi.getRequest()
        if not req:
            return
        svc = mi.getHttpService()
        ana = self.helpers.analyzeRequest(svc, req)
        url = ana.getUrl()
        if not is_in_scope(self.cb, url):
            return
        host = self._service_host(svc)
        headers = ana.getHeaders()
        body = req[ana.getBodyOffset():]
        try:
            body_txt = self.helpers.bytesToString(body)
        except:
            body_txt = ""

        # Authorization + behavioral logout tracking
        saw_auth = False
        for h in headers:
            if h.lower().startswith('authorization:'):
                val = h.split(':',1)[1].strip()
                if val.lower().startswith('bearer '):
                    saw_auth = True
                    token = val[7:].strip()
                    self._track_token('bearer', 'Authorization', token, 'request-header', host, url.toString())
                    self.last_bearer_raw_by_host[host] = token
                    if JWT_RE.search(token):
                        hdr, pl = try_decode_jwt(token)
                        self._record_jwt_deep_issues(host, url.toString(), token, hdr, pl)

        now_e = time.time()
        if saw_auth:
            self.had_auth_recent[host] = now_e
            self.authless_streak[host] = 0
        else:
            self.authless_streak[host] = self.authless_streak.get(host, 0) + 1

        # Cookie header
        for h in headers:
            if h.lower().startswith('cookie:'):
                cookie_line = h.split(':',1)[1].strip()
                for (name, val) in parse_cookies_from_header(cookie_line):
                    if SESSION_COOKIE_HINTS.search(name):
                        tid = self._track_token('cookie', name, val, 'request-header', host, url.toString())
                        self.last_cookie_id_by_host[host] = tid

        # JWTs in body
        for m in JWT_RE.findall(body_txt or ''):
            self._track_token('jwt', 'body-jwt', m, 'request-body', host, url.toString())
            hdr, pl = try_decode_jwt(m)
            self._record_jwt_deep_issues(host, url.toString(), m, hdr, pl)

    def _handle_response(self, mi):
        resp = mi.getResponse()
        if not resp:
            return
        svc = mi.getHttpService()
        ana_req = self.helpers.analyzeRequest(mi)
        url = ana_req.getUrl()
        if not is_in_scope(self.cb, url):
            return
        host = self._service_host(svc)

        ana = self.helpers.analyzeResponse(resp)
        headers = ana.getHeaders()
        body = resp[ana.getBodyOffset():]
        try:
            body_txt = self.helpers.bytesToString(body)
        except:
            body_txt = ""

        # Set-Cookie analysis
        sc_list = parse_set_cookie_lines(headers)
        for sc in sc_list:
            name, val, attrs = sc['name'], sc['value'], sc['attrs']
            if SESSION_COOKIE_HINTS.search(name):
                tid = self._track_token('cookie', name, val, 'response-set-cookie', host, url.toString())
                for iss in cookie_issue_flags(attrs):
                    self._report_issue(host, 'cookie', iss, 'Set-Cookie: %s' % name, url.toString())

        # JWTs in response body
        for m in JWT_RE.findall(body_txt or ''):
            self._track_token('jwt', 'body-jwt', m, 'response-body', host, url.toString())
            hdr, pl = try_decode_jwt(m)
            self._record_jwt_deep_issues(host, url.toString(), m, hdr, pl)
            # Refresh detection + rotation check
            if REFRESH_HINTS.search(url.getPath() or ''):
                self._timeline_event(host, 'REFRESH', 'emitted JWT', url.toString(), self._status_from_headers(headers))
                self._check_jwt_rotation(host, m, url.toString())

        # Flow events
        code = self._status_from_headers(headers)
        path = url.getPath() or ''
        if code in (401, 403):
            self._timeline_event(host, str(code), 'auth failure', url.toString(), code)
        if LOGOUT_HINTS.search(path):
            self._timeline_event(host, 'LOGOUT', 'logout endpoint hit', url.toString(), code)
        if LOGIN_HINTS.search(path) and code in (200, 302):
            self._timeline_event(host, 'LOGIN', 'login response', url.toString(), code)
            self._check_fixation_after_login(host, url.toString())

        # Behavioral LOGOUT: previously authenticated, now N consecutive requests w/o auth
        N = 3
        recent = self.had_auth_recent.get(host)
        if recent and self.authless_streak.get(host, 0) >= N and code in (200, 302, 401, 403):
            self._timeline_event(host, 'LOGOUT', 'auth header disappeared (behavioral)', url.toString(), code)
            # reset so we don’t spam multiple logouts
            self.had_auth_recent.pop(host, None)
            self.authless_streak[host] = 0

    def _status_from_headers(self, headers):
        try:
            line = headers[0]
            parts = line.split()
            return int(parts[1])
        except:
            return 0

    # ---------- trackers / analyzer / flow ----------

    def _track_token(self, ttype, name, value, where, host, url):
        tid = sha1_short(value or '')
        key = (host, ttype, name, tid)
        if key in self.token_seen:
            self.concurrent_counter[key] = self.concurrent_counter.get(key, 1) + 1
            if self.concurrent_counter[key] > 3:
                self._report_issue(host, ttype, 'Token reused many times (possible concurrent sessions)', '%s [%s]' % (name, tid), url)
            return tid
        self.token_seen.add(key)
        row = [now_ts(), host, ttype, name, tid, where, url]
        self.tokens.append(row)
        self._ui_add_row(self.trackerModel, row)
        if ttype in ('jwt','bearer'):
            self.last_jwt_id_by_host[host] = tid
        return tid

    def _report_issue(self, host, itype, desc, evidence, url):
        row = [now_ts(), host, itype, desc, evidence, url]
        self.issues.append(row)
        self._ui_add_row(self.issuesModel, row)

    def _timeline_event(self, host, etype, detail, url, status):
        line = "[%s] %s | %s | %s | %s" % (now_ts(), host, etype, str(status), url)
        self.timeline.append({'t':now_ts(), 'host':host, 'type':etype, 'detail':detail, 'url':url, 'status':status})
        self._ui_append_text(self.timelineArea, line + "\n")

    def _record_jwt_deep_issues(self, host, url, jwt_raw, hdr, pl):
        now_e = time.time()
        for iss in jwt_deep_issues(hdr, pl, now_e):
            ev = None
            try:
                if hdr is not None:
                    ev = 'alg=%s' % (hdr.get('alg'))
            except:
                pass
            self._report_issue(host, 'jwt', iss, ev or 'jwt', url)

    def _check_fixation_after_login(self, host, url):
        pre = self.last_cookie_id_by_host.get(host)
        curr = None
        for i in range(len(self.tokens)-1, -1, -1):
            r = self.tokens[i]
            if r[1]==host and r[2]=='cookie' and r[5]=='response-set-cookie':
                curr = r[4]; break
        if pre and curr and pre == curr:
            self._report_issue(host, 'session', 'Possible session fixation (ID unchanged across login)', 'cookie id=%s' % pre, url)

    def _check_jwt_rotation(self, host, new_jwt_raw, url):
        new_id = sha1_short(new_jwt_raw)
        last = self.last_jwt_id_by_host.get(host)
        if last and last == new_id:
            self._report_issue(host, 'jwt', 'JWT not rotated on refresh', 'id=%s' % new_id, url)
        self.last_jwt_id_by_host[host] = new_id

    # ---------- UI helpers ----------

    def _ui_add_row(self, model, row):
        SwingUtilities.invokeLater(lambda: model.addRow(row))

    def _ui_append_text(self, area, text):
        SwingUtilities.invokeLater(lambda: area.append(text))

    # ---------- Exporters ----------

    def _export_table_csv(self, model):
        chooser = JFileChooser(); chooser.setDialogTitle("Export CSV")
        if chooser.showSaveDialog(self.root) != JFileChooser.APPROVE_OPTION: return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            cols = [model.getColumnName(i) for i in range(model.getColumnCount())]
            with open(path, 'w') as f:
                f.write(','.join(['"%s"'%c.replace('"','""') for c in cols]) + "\n")
                for r in range(model.getRowCount()):
                    cells = [str(model.getValueAt(r, c)) for c in range(model.getColumnCount())]
                    f.write(','.join(['"%s"'%v.replace('"','""') for v in cells]) + "\n")
            JOptionPane.showMessageDialog(self.root, "CSV exported.")
        except Exception as e:
            JOptionPane.showMessageDialog(self.root, "Export failed: %s" % e)

    def _export_table_json(self, model):
        chooser = JFileChooser(); chooser.setDialogTitle("Export JSON")
        if chooser.showSaveDialog(self.root) != JFileChooser.APPROVE_OPTION: return
        path = chooser.getSelectedFile().getAbsolutePath()
        try:
            cols = [model.getColumnName(i) for i in range(model.getColumnCount())]
            data = []
            for r in range(model.getRowCount()):
                obj = {}
                for c in range(model.getColumnCount()):
                    obj[cols[c]] = str(model.getValueAt(r, c))
                data.append(obj)
            with open(path, 'w') as f:
                f.write(json.dumps(data, indent=2))
            JOptionPane.showMessageDialog(self.root, "JSON exported.")
        except Exception as e:
            JOptionPane.showMessageDialog(self.root, "Export failed: %s" % e)

    # ---------- DOT export ----------

    def _export_dot(self, event):
        chooser = JFileChooser(); chooser.setDialogTitle("Save DOT file")
        if chooser.showSaveDialog(self.root) != JFileChooser.APPROVE_OPTION: return
        f = chooser.getSelectedFile()
        try:
            lines = ["digraph AuthFlow {", "rankdir=LR;"]
            by_host = {}
            for e in self.timeline:
                by_host.setdefault(e['host'], []).append(e)
            for host, items in by_host.items():
                lines.append('subgraph "cluster_%s" {' % host.replace('"',''))
                lines.append('label="%s";' % host)
                items_sorted = sorted(items, key=lambda x: x['t'])
                prev = None
                for idx, ev in enumerate(items_sorted):
                    nid = '%s_%d' % (sha1_short(host), idx)
                    label = "%s\\n%s" % (ev['type'], ev['status'])
                    lines.append('%s [shape=box,label="%s"];' % (nid, label))
                    if prev is not None:
                        lines.append('%s -> %s;' % (prev, nid))
                    prev = nid
                lines.append('}')
            lines.append("}")
            with open(f.getAbsolutePath(), 'w') as fw:
                fw.write("\n".join(lines))
            JOptionPane.showMessageDialog(self.root, "DOT exported.")
        except Exception as e:
            JOptionPane.showMessageDialog(self.root, "Export failed: %s" % e)

    # ---------- Context menu ----------

    def createMenuItems(self, invocation):
        items = ArrayList()
        try:
            mi = JMenuItem("SessionSuite: Generate session tests",
                           actionPerformed=lambda e: self._gen_tests(invocation))
            items.add(mi)
        except Exception as e:
            self.cb.printError("[SessionSuite] context menu failed: %s" % e)
        return items

    def _gen_tests(self, invocation):
        try:
            msgs = invocation.getSelectedMessages()
            if not msgs or len(msgs) == 0:
                JOptionPane.showMessageDialog(self.root, "No messages selected.")
                return
            for msg in msgs:
                self._gen_tests_for_message(msg)
            JOptionPane.showMessageDialog(self.root, "Sent mutated requests to Repeater.")
        except Exception as e:
            JOptionPane.showMessageDialog(self.root, "Error: %s" % e)

    def _gen_tests_for_message(self, messageInfo):
        svc = messageInfo.getHttpService()
        host = svc.getHost()
        port = svc.getPort()
        https = svc.getProtocol().lower().startswith('https')

        req = messageInfo.getRequest()
        ana = self.helpers.analyzeRequest(svc, req)
        headers = list(ana.getHeaders())
        body = req[ana.getBodyOffset():]
        body_str = self.helpers.bytesToString(body)

        def build_and_send(hdrs, bstr, suffix):
            new_req = self.helpers.buildHttpMessage(hdrs, bstr)
            caption = "SessionTest: %s" % suffix
            self.cb.sendToRepeater(host, port, https, new_req, caption)

        # strip Cookie
        if self.ccStripCookies.isSelected():
            hdrs = [h for h in headers if not h.lower().startswith('cookie:')]
            build_and_send(hdrs, body_str, "no-cookie")

        # strip Authorization
        if self.ccStripAuth.isSelected():
            hdrs = [h for h in headers if not h.lower().startswith('authorization:')]
            build_and_send(hdrs, body_str, "no-authorization")

        # invalid bearer
        if self.ccInvalidBearer.isSelected():
            hdrs = []; found = False
            for h in headers:
                if h.lower().startswith('authorization:'):
                    found = True
                    hdrs.append('Authorization: Bearer INVALID.TOKEN.VALUE')
                else:
                    hdrs.append(h)
            if not found:
                hdrs.append('Authorization: Bearer INVALID.TOKEN.VALUE')
            build_and_send(hdrs, body_str, "invalid-bearer")

        # corrupt first JWT (header or body)
        if self.ccCorruptJWT.isSelected():
            # header
            hdrs = list(headers); mutated = False
            for i in range(len(hdrs)):
                h = hdrs[i]
                if h.lower().startswith('authorization:') and 'bearer ' in h.lower():
                    val = h.split(':',1)[1].strip()
                    token = val.split(' ',1)[1] if ' ' in val else val
                    m = JWT_RE.search(token)
                    if m:
                        bad = self._corrupt_jwt(token)
                        hdrs[i] = 'Authorization: Bearer ' + bad
                        build_and_send(hdrs, body_str, "corrupt-jwt-header"); mutated = True; break
            if not mutated:
                m = JWT_RE.search(body_str or '')
                if m:
                    bad = self._corrupt_jwt(m.group(0))
                    b2 = body_str.replace(m.group(0), bad, 1)
                    build_and_send(headers, b2, "corrupt-jwt-body")

        # replay last seen bearer
        if self.ccReplayLast.isSelected():
            hdrs = list(headers)
            last_bearer = self.last_bearer_raw_by_host.get(host)
            if last_bearer:
                # replace or add Authorization
                replaced = False
                for i in range(len(hdrs)):
                    if hdrs[i].lower().startswith('authorization:'):
                        hdrs[i] = 'Authorization: Bearer %s' % last_bearer; replaced = True; break
                if not replaced:
                    hdrs.append('Authorization: Bearer %s' % last_bearer)
                build_and_send(hdrs, body_str, "replay-last-bearer")
            else:
                build_and_send(headers, body_str, "replay-no-bearer-available")

        # expired JWT (set exp in the past)
        if self.ccExpiredJWT.isSelected():
            hdrs = list(headers); mutated = False
            for i in range(len(hdrs)):
                if hdrs[i].lower().startswith('authorization:') and 'bearer ' in hdrs[i].lower():
                    tok = hdrs[i].split(':',1)[1].strip().split(' ',1)[1]
                    if JWT_RE.search(tok):
                        bad = synthesize_expired_jwt(tok)
                        hdrs[i] = 'Authorization: Bearer ' + bad
                        build_and_send(hdrs, body_str, "expired-jwt"); mutated = True; break
            if not mutated:
                m = JWT_RE.search(body_str or '')
                if m:
                    bad = synthesize_expired_jwt(m.group(0))
                    b2 = body_str.replace(m.group(0), bad, 1)
                    build_and_send(headers, b2, "expired-jwt-body")

    def _corrupt_jwt(self, jwt_str):
        try:
            parts = jwt_str.split('.')
            if len(parts) >= 2 and len(parts[1]) > 2:
                mid = parts[1]
                flip = 'A' if mid[0] != 'A' else 'B'
                parts[1] = flip + mid[1:]
                return '.'.join(parts)
            return jwt_str + 'A'
        except:
            return jwt_str + 'A'
