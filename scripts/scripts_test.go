// Package scripts tests the deployment shell scripts against fake gcloud,
// docker and curl binaries that record every call. Nothing reaches Google
// Cloud; the tests check which commands the scripts would run.
package scripts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
)

const (
	fakeURL    = "https://email-mcp-123456789012.europe-west1.run.app" // deterministic form
	legacyURL  = "https://email-mcp-abcdefghij-ew.a.run.app"
	fakeDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	baseConfig = `# test config
PROJECT_ID=test-project-1
MAIL_USERNAME=me@example.org
OAUTH_CLIENT_ID=claude-0123456789abcdef
SEND_ALLOWLIST="example.org,friend@example.net"
MAX_SENDS_PER_DAY=5
`
)

// The fakes log argv (NUL-separated) to $FAKE_STATE/call.NNNN and answer
// from marker files in $FAKE_STATE.
const fakePrelude = `#!/usr/bin/env bash
S=$FAKE_STATE
n=$(( $(cat "$S/count" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$S/count"
id=$(printf %04d "$n")
printf '%s\0' "$(basename "$0")" "$@" > "$S/call.$id"
args=" $* "
`

const fakeGcloud = fakePrelude + `case $args in
*" config get-value account "*) echo owner@example.com ;;
*" run services list "*) [[ -f $S/service ]] && echo email-mcp ;;
*" run services describe "*) [[ -f $S/service ]] || exit 1
	printf '{"metadata":{"annotations":{"run.googleapis.com/urls":"[\\"%s\\",\\"%s\\"]"}},"status":{"url":"%s"},' "$FAKE_LEGACY_URL" "$FAKE_URL" "$FAKE_LEGACY_URL"
	printf '"spec":{"template":{"spec":{"containers":[{"env":[{"name":"BASE_URL","value":"%s"}]}]}}}}' "$(cat "$S/baseurl" 2>/dev/null)" ;;
*" run deploy "*) touch "$S/service"; : > "$S/baseurl"
	for a in "$@"; do [[ $a == --set-env-vars=* ]] || continue
		IFS='|' read -ra kv <<<"${a#--set-env-vars=^|^}"
		for p in "${kv[@]}"; do [[ $p == BASE_URL=* ]] && printf '%s' "${p#BASE_URL=}" > "$S/baseurl"; done
	done ;;
*" artifacts docker images describe "*) [[ -f $S/pushed ]] && echo "$FAKE_DIGEST" || exit 1 ;;
*" artifacts repositories describe "*) exit 1 ;;
*" iam service-accounts describe "*) exit 1 ;;
*" secrets describe "*) exit 1 ;;
*" secrets versions add "*) cat > "$S/stdin.$id" ;;
*" secrets versions list "*" --limit=1 "*) [[ -f $S/nosecrets ]] || echo 3 ;;
*" secrets versions list "*) echo projects/1/secrets/x/versions/3 ;;
esac
exit 0
`

const fakeDocker = fakePrelude + `[[ $1 == push ]] && touch "$S/pushed"
exit 0
`

const fakeCurl = fakePrelude + `url=${!#}
case $args in
*" -w "*) printf 401 ;;
*) case $url in
	*/healthz) echo ok ;;
	*/.well-known/oauth-protected-resource/mcp) printf '{"resource":"%s/mcp"}' "${FAKE_RESOURCE_BASE:-${url%%/.well-known/*}}" ;;
	*) exit 22 ;;
	esac ;;
esac
`

type sandbox struct {
	t     *testing.T
	root  string // repository root
	state string
	env   []string
}

func newSandbox(t *testing.T, config string) *sandbox {
	t.Helper()
	for _, tool := range []string{"bash", "git", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin, state := filepath.Join(dir, "bin"), filepath.Join(dir, "state")
	for _, d := range []string{bin, state} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, src := range map[string]string{"gcloud": fakeGcloud, "docker": fakeDocker, "curl": fakeCurl} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(src), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "deploy.env")
	if err := os.WriteFile(cfg, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return &sandbox{t: t, root: root, state: state, env: []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		// HOME is isolated; Go keeps the caller's caches, so `go run` in
		// gcp-secrets.sh neither rebuilds the world nor downloads modules.
		"HOME=" + dir, "GOCACHE=" + goEnv(t, "GOCACHE"), "GOMODCACHE=" + goEnv(t, "GOMODCACHE"),
		"GOPATH=" + goEnv(t, "GOPATH"), "GOFLAGS=-mod=readonly", "GOPROXY=off", "GOTOOLCHAIN=local",
		"FAKE_STATE=" + state, "FAKE_URL=" + fakeURL, "FAKE_LEGACY_URL=" + legacyURL, "FAKE_DIGEST=" + fakeDigest,
		"CONFIG=" + cfg, "YES=1", "ALLOW_DIRTY=1",
	}}
}

func goEnv(t *testing.T, key string) string {
	t.Helper()
	out, err := exec.Command("go", "env", key).Output()
	if err != nil {
		t.Skipf("go env %s: %v", key, err)
	}
	return strings.TrimSpace(string(out))
}

func (s *sandbox) mark(name string) { s.markValue(name, "") }

func (s *sandbox) markValue(name, value string) {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.state, name), []byte(value), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

// run executes a script with stdin (not a terminal) and returns its output.
func (s *sandbox) run(stdin string, script string, args ...string) (string, error) {
	s.t.Helper()
	cmd := exec.Command(filepath.Join(s.root, "scripts", script), args...)
	cmd.Env = s.env
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// calls returns the recorded invocations of program (any program if
// empty) in order, only those whose arguments contain all of words.
func (s *sandbox) calls(program string, words ...string) [][]string {
	s.t.Helper()
	files, _ := filepath.Glob(filepath.Join(s.state, "call.*"))
	sort.Strings(files)
	var out [][]string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			s.t.Fatal(err)
		}
		argv := strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
		if (program == "" || argv[0] == program) && containsAll(argv[1:], words...) {
			out = append(out, argv)
		}
	}
	return out
}

func containsAll(argv []string, words ...string) bool {
	for _, w := range words {
		if !slices.Contains(argv, w) {
			return false
		}
	}
	return true
}

// flag returns the value of --name=value in argv.
func flag(argv []string, name string) (string, bool) {
	for _, a := range argv {
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v, true
		}
	}
	return "", false
}

// envVars decodes gcloud's ^|^K=V|K=V syntax.
func envVars(t *testing.T, v string) map[string]string {
	t.Helper()
	rest, ok := strings.CutPrefix(v, "^|^")
	if !ok {
		t.Fatalf("env vars without the ^|^ delimiter: %q", v)
	}
	m := map[string]string{}
	for kv := range strings.SplitSeq(rest, "|") {
		k, val, _ := strings.Cut(kv, "=")
		m[k] = val
	}
	return m
}

const wantSecrets = "MAIL_PASSWORD=email-mcp-mail-password:3,TOKEN_SIGNING_KEY=email-mcp-token-signing-key:3," +
	"OAUTH_CLIENT_SECRET=email-mcp-oauth-client-secret:3,AUTHORIZE_PASSWORD_HASH=email-mcp-authorize-password-hash:3"

func checkDeployCall(t *testing.T, argv []string, wantBaseURL string) {
	t.Helper()
	for _, f := range []string{"--allow-unauthenticated", "--cpu-throttling", "--quiet", "--project=test-project-1",
		"--region=europe-west1", "--min-instances=0", "--max-instances=1", "--max=1", "--cpu=1", "--memory=256Mi", "--timeout=60",
		"--execution-environment=gen1", "--ingress=all", "--port=8080",
		"--service-account=email-mcp-run@test-project-1.iam.gserviceaccount.com",
		"--image=europe-west1-docker.pkg.dev/test-project-1/email-mcp/email-mcp@" + fakeDigest,
		"--set-secrets=" + wantSecrets,
	} {
		if !slices.Contains(argv, f) {
			t.Errorf("deploy call lacks %s:\n%q", f, argv)
		}
	}
	raw, _ := flag(argv, "set-env-vars")
	env := envVars(t, raw)
	want := map[string]string{"MAIL_USERNAME": "me@example.org", "OAUTH_CLIENT_ID": "claude-0123456789abcdef",
		"SEND_ALLOWLIST": "example.org,friend@example.net", "MAX_SENDS_PER_DAY": "5"}
	if wantBaseURL != "" {
		want["BASE_URL"] = wantBaseURL
	}
	if len(env) != len(want) {
		t.Errorf("env = %v, want %v", env, want)
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("env %s = %q, want %q", k, env[k], v)
		}
	}
}

func TestDeployFirstTimeIsTwoStep(t *testing.T) {
	s := newSandbox(t, baseConfig)
	out, err := s.run("", "deploy.sh")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	deploys := s.calls("gcloud", "run", "deploy")
	if len(deploys) != 2 {
		t.Fatalf("%d deploy calls, want 2", len(deploys))
	}
	checkDeployCall(t, deploys[0], "")
	checkDeployCall(t, deploys[1], fakeURL)

	builds := s.calls("docker", "build")
	if len(builds) != 1 || !containsAll(builds[0], "--platform", "linux/amd64", "--provenance=false", "--sbom=false", s.root) {
		t.Fatalf("docker build = %q", builds)
	}
	if v := builds[0][slices.Index(builds[0], "--build-arg")+1]; !regexp.MustCompile(`^VERSION=[0-9a-f]{12}(-dirty-\d{14})?$`).MatchString(v) {
		t.Errorf("build arg %q", v)
	}
	if len(s.calls("docker", "push")) != 1 {
		t.Error("image not pushed")
	}
	// Every gcloud call is pinned to the project and never prompts.
	for _, c := range s.calls("gcloud") {
		if slices.Contains(c, "config") {
			continue
		}
		if !containsAll(c, "--project=test-project-1", "--quiet") {
			t.Errorf("gcloud call without --project/--quiet: %q", c)
		}
	}
	for _, want := range []string{"URL            " + fakeURL + "/mcp", "Client ID      claude-0123456789abcdef"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestDeployLaterIsOneStepAndReusesImage(t *testing.T) {
	s := newSandbox(t, baseConfig)
	s.mark("service")
	s.markValue("baseurl", fakeURL)
	s.mark("pushed")
	if out, err := s.run("", "deploy.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	deploys := s.calls("gcloud", "run", "deploy")
	if len(deploys) != 1 {
		t.Fatalf("%d deploy calls, want 1", len(deploys))
	}
	checkDeployCall(t, deploys[0], fakeURL)
	if n := len(s.calls("docker")); n != 0 {
		t.Errorf("%d docker calls for an already pushed image", n)
	}
}

// A later deploy keeps the BASE_URL the service already uses, even when
// another URL form is listed first: changing it would break every token and
// the connector.
func TestDeployKeepsExistingBaseURL(t *testing.T) {
	s := newSandbox(t, baseConfig)
	s.mark("service")
	s.markValue("baseurl", legacyURL)
	s.env = append(s.env, "FAKE_RESOURCE_BASE="+legacyURL)
	if out, err := s.run("", "deploy.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	deploys := s.calls("gcloud", "run", "deploy")
	if len(deploys) != 1 {
		t.Fatalf("%d deploy calls, want 1", len(deploys))
	}
	checkDeployCall(t, deploys[0], legacyURL)
}

// A service left in setup mode (an earlier step 2 failed) is finished in
// two steps, like a new one.
func TestDeployFinishesSetupMode(t *testing.T) {
	s := newSandbox(t, baseConfig)
	s.mark("service")
	if out, err := s.run("", "deploy.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	deploys := s.calls("gcloud", "run", "deploy")
	if len(deploys) != 2 {
		t.Fatalf("%d deploy calls, want 2", len(deploys))
	}
	checkDeployCall(t, deploys[1], fakeURL)
}

func TestDeployWithoutAllUsers(t *testing.T) {
	s := newSandbox(t, baseConfig+"PUBLIC_ACCESS=no-invoker-iam-check\n")
	if out, err := s.run("", "deploy.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, c := range s.calls("gcloud", "run", "deploy") {
		if !slices.Contains(c, "--no-invoker-iam-check") || slices.Contains(c, "--allow-unauthenticated") {
			t.Fatalf("deploy call = %q", c)
		}
	}
}

// Variables exported in the caller's shell never reach a deployment; only
// deploy.env counts.
func TestDeployIgnoresCallerEnvironment(t *testing.T) {
	s := newSandbox(t, baseConfig)
	s.env = append(s.env, "BASE_URL=http://127.0.0.1:8080", "LOG_LEVEL=debug", "MAIL_PASSWORD=leak", "PROJECT_ID=other-project")
	if out, err := s.run("", "deploy.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	deploys := s.calls("gcloud", "run", "deploy")
	if len(deploys) != 2 {
		t.Fatalf("%d deploy calls, want 2", len(deploys))
	}
	checkDeployCall(t, deploys[1], fakeURL) // exact env: no LOG_LEVEL, no MAIL_PASSWORD
	for _, c := range s.calls("") {
		if strings.Contains(strings.Join(c, " "), "other-project") || strings.Contains(strings.Join(c, " "), "leak") {
			t.Fatalf("caller environment leaked into %q", c)
		}
	}
}

func TestDeployBaseURLOverride(t *testing.T) {
	s := newSandbox(t, baseConfig+"BASE_URL=https://mail.example.org\n")
	s.env = append(s.env, "FAKE_RESOURCE_BASE=https://mail.example.org")
	if out, err := s.run("", "deploy.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	deploys := s.calls("gcloud", "run", "deploy")
	if len(deploys) != 1 {
		t.Fatalf("%d deploy calls, want 1", len(deploys))
	}
	checkDeployCall(t, deploys[0], "https://mail.example.org")
}

func TestDeployVerifiesTheResource(t *testing.T) {
	s := newSandbox(t, baseConfig)
	s.env = append(s.env, "FAKE_RESOURCE_BASE=https://elsewhere.example")
	out, err := s.run("", "deploy.sh")
	if err == nil || !strings.Contains(out, "does not name "+fakeURL+"/mcp") {
		t.Fatalf("resource mismatch not detected: %v\n%s", err, out)
	}
}

func TestDeployNeedsSecretVersions(t *testing.T) {
	s := newSandbox(t, baseConfig)
	s.mark("nosecrets")
	out, err := s.run("", "deploy.sh")
	if err == nil || !strings.Contains(out, "run scripts/gcp-secrets.sh MAIL_PASSWORD") {
		t.Fatalf("missing secret not reported: %v\n%s", err, out)
	}
	if n := len(s.calls("gcloud", "run", "deploy")) + len(s.calls("docker")); n != 0 {
		t.Fatalf("%d build/deploy calls despite missing secrets", n)
	}
}

func TestDeployAsksWithoutYes(t *testing.T) {
	s := newSandbox(t, baseConfig)
	s.env = slices.DeleteFunc(s.env, func(e string) bool { return e == "YES=1" })
	out, err := s.run("", "deploy.sh")
	if err == nil || !strings.Contains(out, "set YES=1") {
		t.Fatalf("ran without confirmation: %v\n%s", err, out)
	}
	if n := len(s.calls("gcloud", "run", "deploy")) + len(s.calls("docker")); n != 0 {
		t.Fatalf("%d build/deploy calls without confirmation", n)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, tc := range map[string]struct{ config, want string }{
		"secret in file":   {baseConfig + "MAIL_PASSWORD=hunter2\n", "MAIL_PASSWORD is a secret"},
		"exported secret":  {baseConfig + "OAUTH_CLIENT_SECRET=x\n", "OAUTH_CLIENT_SECRET is a secret"},
		"unknown key":      {baseConfig + "MAIL_PASWORD=typo\n", "unknown setting MAIL_PASWORD"},
		"shell code":       {baseConfig + "$(touch /tmp/pwned)\n", "expected KEY=value"},
		"bad project":      {strings.Replace(baseConfig, "test-project-1", "Bad_Project", 1), "not a valid project ID"},
		"delimiter":        {baseConfig + "MAIL_FROM_NAME=a|b\n", "must not contain '|'"},
		"no username":      {strings.Replace(baseConfig, "MAIL_USERNAME=me@example.org\n", "", 1), "set MAIL_USERNAME"},
		"bad client id":    {strings.Replace(baseConfig, "claude-0123456789abcdef", "short", 1), "OAUTH_CLIENT_ID must be"},
		"bad service name": {baseConfig + "SERVICE=Email_MCP\n", "not a valid Cloud Run service name"},
		"bad region":       {baseConfig + "REGION=europe west1\n", "not a valid region"},
		"bad account id":   {baseConfig + "RUNTIME_SA_NAME=sa\n", "not a valid account ID"},
		"bad access mode":  {baseConfig + "PUBLIC_ACCESS=everyone\n", "PUBLIC_ACCESS must be"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSandbox(t, tc.config)
			for _, script := range []string{"deploy.sh", "gcp-bootstrap.sh", "gcp-registry.sh"} {
				out, err := s.run("", script)
				if err == nil || !strings.Contains(out, tc.want) {
					t.Errorf("%s: want error %q, got %v\n%s", script, tc.want, err, out)
				}
			}
			if n := len(s.calls("")); n != 0 {
				t.Errorf("%d external calls despite invalid config", n)
			}
		})
	}
}

func TestSecretsGoThroughStdinOnly(t *testing.T) {
	s := newSandbox(t, baseConfig)
	const pw = "correct horse battery staple, with spaces"
	out, err := s.run(pw+"\n", "gcp-secrets.sh", "MAIL_PASSWORD")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	adds := s.calls("gcloud", "secrets", "versions", "add", "email-mcp-mail-password", "--data-file=-")
	if len(adds) != 1 {
		t.Fatalf("versions add calls = %q", adds)
	}
	stored, _ := filepath.Glob(filepath.Join(s.state, "stdin.*"))
	if len(stored) != 1 {
		t.Fatal("no value reached gcloud's stdin")
	}
	if b, _ := os.ReadFile(stored[0]); string(b) != pw {
		t.Fatalf("stored %q, want %q", b, pw)
	}
	for _, c := range s.calls("") {
		if strings.Contains(strings.Join(c, " "), "horse") {
			t.Fatalf("secret value in argv: %q", c)
		}
	}
	if len(s.calls("gcloud", "secrets", "create", "email-mcp-mail-password", "--replication-policy=user-managed", "--locations=europe-west1")) != 1 {
		t.Error("secret not created in the region")
	}
	if len(s.calls("gcloud", "secrets", "add-iam-policy-binding", "email-mcp-mail-password",
		"--member=serviceAccount:email-mcp-run@test-project-1.iam.gserviceaccount.com", "--role=roles/secretmanager.secretAccessor")) != 1 {
		t.Error("runtime service account not granted access to this secret")
	}
}

func TestSecretsValidateBeforeStoring(t *testing.T) {
	for key, value := range map[string]string{
		"TOKEN_SIGNING_KEY":       "too-short",
		"OAUTH_CLIENT_SECRET":     "short secret with spaces",
		"MAIL_PASSWORD":           "",
		"AUTHORIZE_PASSWORD_HASH": "short",
	} {
		t.Run(key, func(t *testing.T) {
			s := newSandbox(t, baseConfig)
			if out, err := s.run(value+"\n", "gcp-secrets.sh", key); err == nil {
				t.Fatalf("invalid value accepted:\n%s", out)
			}
			if n := len(s.calls("gcloud", "secrets")); n != 0 {
				t.Fatalf("%d Secret Manager calls for an invalid value", n)
			}
		})
	}
}

func TestSecretsStoresPasswordHashNotPassword(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not in PATH")
	}
	s := newSandbox(t, baseConfig)
	const pw = "a long owner password 123"
	if out, err := s.run(pw+"\n", "gcp-secrets.sh", "AUTHORIZE_PASSWORD_HASH"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	stored, _ := filepath.Glob(filepath.Join(s.state, "stdin.*"))
	if len(stored) != 1 {
		t.Fatal("nothing stored")
	}
	b, _ := os.ReadFile(stored[0])
	if !strings.HasPrefix(string(b), "$argon2id$v=19$m=65536,t=3,p=1$") || strings.Contains(string(b), pw) || strings.HasSuffix(string(b), "\n") {
		t.Fatalf("stored %q", b)
	}
}

func TestRegistryCleanupPolicy(t *testing.T) {
	s := newSandbox(t, baseConfig)
	if out, err := s.run("", "gcp-registry.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(s.calls("gcloud", "artifacts", "repositories", "create", "email-mcp", "--repository-format=docker",
		"--location=europe-west1", "--immutable-tags")) != 1 {
		t.Error("repository not created as expected")
	}
	policy := filepath.Join(s.root, "deploy", "cleanup-policy.json")
	if len(s.calls("gcloud", "artifacts", "repositories", "set-cleanup-policies", "email-mcp", "--location=europe-west1",
		"--policy="+policy, "--no-dry-run")) != 1 {
		t.Error("cleanup policy not applied (enforced, not dry run)")
	}
	b, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	var rules []struct {
		Action             struct{ Type string }
		MostRecentVersions *struct{ KeepCount int }
		Condition          *struct{ TagState string }
	}
	if err := json.Unmarshal(b, &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Action.Type != "Keep" || rules[0].MostRecentVersions == nil || rules[0].MostRecentVersions.KeepCount != 2 ||
		rules[1].Action.Type != "Delete" || rules[1].Condition == nil || rules[1].Condition.TagState != "ANY" {
		t.Fatalf("policy = %s", b)
	}
}

func TestBootstrap(t *testing.T) {
	s := newSandbox(t, baseConfig)
	if out, err := s.run("", "gcp-bootstrap.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(s.calls("gcloud", "services", "enable", "run.googleapis.com", "artifactregistry.googleapis.com",
		"secretmanager.googleapis.com", "iam.googleapis.com")) != 1 {
		t.Error("APIs not enabled")
	}
	if len(s.calls("gcloud", "iam", "service-accounts", "create", "email-mcp-run")) != 1 {
		t.Error("runtime service account not created")
	}
	// The runtime account gets no project-level role.
	if n := len(s.calls("gcloud", "projects", "add-iam-policy-binding")); n != 0 {
		t.Error("project-level role granted")
	}
}

func TestGenSecrets(t *testing.T) {
	root, _ := filepath.Abs("..")
	script := filepath.Join(root, "scripts", "gen-secrets.sh")
	// Not a terminal: refuses and prints nothing on stdout.
	cmd := exec.Command(script)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err == nil || stdout.Len() != 0 {
		t.Fatalf("ran with stdout not a terminal: %v %q", err, stdout.String())
	}
	if _, err := exec.LookPath("script"); err != nil || runtime.GOOS != "linux" {
		t.Skip("needs util-linux script for a pseudo-terminal")
	}
	gen := func() map[string]string {
		out, err := exec.Command("script", "-qec", script, "/dev/null").Output()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		m := map[string]string{}
		for line := range strings.SplitSeq(strings.ReplaceAll(string(out), "\r", ""), "\n") {
			if f := strings.Fields(line); len(f) == 2 && slices.Contains([]string{"TOKEN_SIGNING_KEY", "OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET"}, f[0]) {
				m[f[0]] = f[1]
			}
		}
		return m
	}
	a, b := gen(), gen()
	key, err := base64.StdEncoding.DecodeString(a["TOKEN_SIGNING_KEY"])
	if err != nil || len(key) != 32 {
		t.Errorf("signing key %q: %v (%d bytes)", a["TOKEN_SIGNING_KEY"], err, len(key))
	}
	if !regexp.MustCompile(`^claude-[0-9a-f]{24}$`).MatchString(a["OAUTH_CLIENT_ID"]) {
		t.Errorf("client id %q", a["OAUTH_CLIENT_ID"])
	}
	if sec, err := base64.RawURLEncoding.DecodeString(a["OAUTH_CLIENT_SECRET"]); err != nil || len(sec) != 32 {
		t.Errorf("client secret %q: %v", a["OAUTH_CLIENT_SECRET"], err)
	}
	if len(a) != 3 {
		t.Fatalf("output = %v", a)
	}
	for k := range a {
		if a[k] == b[k] {
			t.Errorf("%s repeated across runs", k)
		}
	}
}
