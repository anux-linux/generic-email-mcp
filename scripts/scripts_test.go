// Package scripts tests the deployment shell scripts against fake gcloud,
// docker and curl binaries that record every call. Nothing reaches Google
// Cloud; the tests check which commands the scripts would run.
package scripts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
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
*" projects describe "*) echo 123456789012 ;;
*" workload-identity-pools providers describe "*) [[ -f $S/provider ]] && cat "$S/provider" || exit 1 ;;
*" workload-identity-pools providers list "*) [[ -f $S/nolist ]] && exit 1; [[ -f $S/providers ]] && cat "$S/providers" ;;
*" workload-identity-pools describe "*) [[ -f $S/pool ]] && cat "$S/pool" || exit 1 ;;
*" auth login "*) for a in "$@"; do [[ $a == --cred-file=* ]] && cp -p "${a#--cred-file=}" "$S/credentials.json"; done ;;
*" artifacts repositories describe "*) exit 1 ;;
*" iam service-accounts describe "*) exit 1 ;;
*" secrets describe "*) [[ -f $S/secrets ]] || exit 1 ;;
*" secrets versions add "*) cat > "$S/stdin.$id" ;;
*" secrets versions list "*" --limit=1 "*) [[ -f $S/nosecrets ]] || echo 3 ;;
*" secrets versions list "*) echo projects/1/secrets/x/versions/3 ;;
esac
exit 0
`

const fakeDocker = fakePrelude + `[[ $1 == push ]] && touch "$S/pushed"
exit 0
`

// A download (-o FILE) never delivers the pinned gcloud tarball.
const fakeCurl = fakePrelude + `url=${!#}
case $args in
*" -w "*) printf 401 ;;
*" -o "*) prev=""
	for a in "$@"; do [[ $prev == -o ]] && echo "not the pinned tarball" > "$a"; prev=$a; done ;;
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
	checkDeployCallAccess(t, argv, wantBaseURL, "--allow-unauthenticated")
}

// checkDeployCallAccess is checkDeployCall with the public access flag
// expected (none if empty).
func checkDeployCallAccess(t *testing.T, argv []string, wantBaseURL, access string) {
	t.Helper()
	for _, f := range []string{"--allow-unauthenticated", "--no-invoker-iam-check"} {
		if slices.Contains(argv, f) != (f == access) {
			t.Errorf("deploy call: %s present = %v, want %v:\n%q", f, !(f == access), f == access, argv)
		}
	}
	for _, f := range []string{"--cpu-throttling", "--quiet", "--project=test-project-1",
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
		"bad repository":   {baseConfig + "CD_REPO=no-slash\n", "CD_REPO must be OWNER/REPOSITORY"},
		"quote in repo id": {baseConfig + "CD_REPO_ID=1' && true && '1\n", "CD_REPO_ID must be the numeric"},
		"reserved pool id": {baseConfig + "WIF_POOL=gcp-github\n", "not starting with gcp-"},
		"shared accounts":  {baseConfig + "DEPLOY_SA_NAME=email-mcp-run\n", "DEPLOY_SA_NAME must differ"},
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

// --- deploys from GitHub Actions ----------------------------------------------

const (
	cdConfig    = baseConfig + "CD_REPO=anux-linux/generic-email-mcp\nCD_REPO_ID=1427120410\nCD_OWNER_ID=838468\n"
	wifProvider = "projects/123456789012/locations/global/workloadIdentityPools/email-mcp/providers/github"
	deploySA    = "email-mcp-deploy@test-project-1.iam.gserviceaccount.com"
	wantCond    = "assertion.repository_id == '1427120410' && assertion.repository_owner_id == '838468'" +
		" && assertion.ref == 'refs/heads/main' && assertion.environment == 'production'" +
		" && assertion.workflow_ref == 'anux-linux/generic-email-mcp/.github/workflows/deploy.yml@refs/heads/main'" +
		" && assertion.runner_environment == 'github-hosted'"
)

// bindings returns every add-iam-policy-binding call as
// "<resource kind> <resource> <member> <role>".
func (s *sandbox) bindings() []string {
	s.t.Helper()
	var out []string
	for _, c := range s.calls("gcloud", "add-iam-policy-binding") {
		i := slices.Index(c, "add-iam-policy-binding")
		member, _ := flag(c, "member")
		role, _ := flag(c, "role")
		out = append(out, strings.Join(c[3:i], " ")+" "+c[i+1]+" "+member+" "+role)
	}
	sort.Strings(out)
	return out
}

func TestGitHubSetup(t *testing.T) {
	s := newSandbox(t, cdConfig)
	s.mark("service")
	s.mark("secrets")
	out, err := s.run("", "gcp-github.sh")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(s.calls("gcloud", "services", "enable", "iam.googleapis.com", "cloudresourcemanager.googleapis.com",
		"iamcredentials.googleapis.com", "sts.googleapis.com")) != 1 {
		t.Error("APIs not enabled")
	}
	if len(s.calls("gcloud", "iam", "workload-identity-pools", "create", "email-mcp", "--location=global")) != 1 {
		t.Error("pool not created")
	}
	creates := s.calls("gcloud", "workload-identity-pools", "providers", "create-oidc", "github",
		"--workload-identity-pool=email-mcp", "--location=global", "--issuer-uri=https://token.actions.githubusercontent.com",
		"--attribute-mapping=google.subject=assertion.sub,attribute.repository_id=assertion.repository_id")
	if len(creates) != 1 {
		t.Fatalf("provider create calls = %q", s.calls("gcloud", "providers"))
	}
	if c, _ := flag(creates[0], "attribute-condition"); c != wantCond {
		t.Errorf("attribute condition\n got %s\nwant %s", c, wantCond)
	}
	if len(s.calls("gcloud", "iam", "service-accounts", "create", "email-mcp-deploy")) != 1 {
		t.Error("deployer service account not created")
	}
	// Least privilege: exactly these grants, each on one resource; no
	// project-level role.
	member := "serviceAccount:" + deploySA
	want := []string{
		"artifacts repositories email-mcp " + member + " roles/artifactregistry.writer",
		"iam service-accounts " + deploySA + " principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/email-mcp/attribute.repository_id/1427120410 roles/iam.workloadIdentityUser",
		"iam service-accounts email-mcp-run@test-project-1.iam.gserviceaccount.com " + member + " roles/iam.serviceAccountUser",
		"run services email-mcp " + member + " roles/run.developer",
	}
	for _, key := range []string{"authorize-password-hash", "mail-password", "oauth-client-secret", "token-signing-key"} {
		want = append(want, "secrets email-mcp-"+key+" "+member+" roles/secretmanager.viewer")
	}
	sort.Strings(want)
	if got := s.bindings(); !slices.Equal(got, want) {
		t.Errorf("bindings\n got %q\nwant %q", got, want)
	}
	if n := len(s.calls("gcloud", "projects", "add-iam-policy-binding")); n != 0 {
		t.Error("project-level role granted")
	}
	for _, w := range []string{"GCP_WIF_PROVIDER   " + wifProvider, "GCP_DEPLOY_SA      " + deploySA,
		"gh secret set DEPLOY_ENV --repo anux-linux/generic-email-mcp --env production < deploy.env"} {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

// Re-running keeps the pool and brings the provider's condition up to date.
func TestGitHubSetupUpdatesProvider(t *testing.T) {
	s := newSandbox(t, cdConfig)
	s.mark("service")
	s.mark("secrets")
	s.markValue("pool", "ACTIVE")
	s.markValue("provider", "ACTIVE")
	s.markValue("providers", "github\n")
	if out, err := s.run("", "gcp-github.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if n := len(s.calls("gcloud", "create")) + len(s.calls("gcloud", "create-oidc")); n != 1 { // the service account
		t.Errorf("%d create calls, want 1: %q", n, s.calls("gcloud"))
	}
	updates := s.calls("gcloud", "providers", "update-oidc", "github", "--workload-identity-pool=email-mcp",
		"--issuer-uri=https://token.actions.githubusercontent.com")
	if len(updates) != 1 {
		t.Fatalf("update-oidc calls = %q", updates)
	}
	if c, _ := flag(updates[0], "attribute-condition"); c != wantCond {
		t.Errorf("attribute condition %s", c)
	}
}

func TestGitHubSetupRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		config string
		marks  map[string]string
		want   string
	}{
		"no service":       {cdConfig, map[string]string{"secrets": ""}, "deploy it once with scripts/deploy.sh"},
		"no secrets":       {cdConfig, map[string]string{"service": ""}, "run scripts/gcp-secrets.sh MAIL_PASSWORD"},
		"no repository":    {baseConfig, map[string]string{"service": "", "secrets": ""}, "set CD_REPO, CD_REPO_ID and CD_OWNER_ID"},
		"deleted provider": {cdConfig, map[string]string{"service": "", "secrets": "", "pool": "ACTIVE", "provider": "DELETED"}, "providers undelete github"},
		"deleted pool":     {cdConfig, map[string]string{"service": "", "secrets": "", "pool": "DELETED"}, "workload-identity-pools undelete email-mcp"},
		// Another provider in the pool would map tokens of this repository
		// to the same principals, bypassing our condition.
		"shared pool": {cdConfig, map[string]string{"service": "", "secrets": "", "pool": "ACTIVE", "provider": "ACTIVE",
			"providers": "github\nother-ci\n"}, "also holds the provider(s) other-ci"},
		"unlistable pool": {cdConfig, map[string]string{"service": "", "secrets": "", "pool": "ACTIVE", "nolist": ""},
			"cannot list the providers of pool email-mcp"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSandbox(t, tc.config)
			for k, v := range tc.marks {
				s.markValue(k, v)
			}
			out, err := s.run("", "gcp-github.sh")
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("want error %q, got %v\n%s", tc.want, err, out)
			}
			if n := len(s.calls("gcloud", "add-iam-policy-binding")) + len(s.calls("gcloud", "create-oidc")) + len(s.calls("gcloud", "update-oidc")); n != 0 {
				t.Errorf("%d provider or binding changes despite the error", n)
			}
		})
	}
}

// UPDATE_ONLY (CI): no project-wide listing, public access left alone,
// everything else as declarative as a local deploy.
func TestDeployUpdateOnly(t *testing.T) {
	s := newSandbox(t, baseConfig)
	s.mark("service")
	s.markValue("baseurl", fakeURL)
	s.env = append(s.env, "UPDATE_ONLY=1")
	if out, err := s.run("", "deploy.sh"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if n := len(s.calls("gcloud", "run", "services", "list")); n != 0 {
		t.Errorf("%d service list calls", n)
	}
	deploys := s.calls("gcloud", "run", "deploy")
	if len(deploys) != 1 {
		t.Fatalf("%d deploy calls, want 1", len(deploys))
	}
	checkDeployCallAccess(t, deploys[0], fakeURL, "")
}

func TestDeployUpdateOnlyNeedsService(t *testing.T) {
	s := newSandbox(t, baseConfig)
	s.env = append(s.env, "UPDATE_ONLY=1")
	out, err := s.run("", "deploy.sh")
	if err == nil || !strings.Contains(out, "cannot read service email-mcp") {
		t.Fatalf("missing service not reported: %v\n%s", err, out)
	}
	if n := len(s.calls("gcloud", "run", "deploy")) + len(s.calls("docker")); n != 0 {
		t.Fatalf("%d build/deploy calls without a service", n)
	}
}

// checkMasked asserts that each value is masked before any printed line
// contains it. Mask commands themselves are consumed by the runner.
func checkMasked(t *testing.T, out string, values ...string) {
	t.Helper()
	for _, v := range values {
		masked, used := false, false
		for line := range strings.SplitSeq(out, "\n") {
			switch {
			case line == "::add-mask::"+v:
				masked = true
			case strings.HasPrefix(line, "::add-mask::"):
			case strings.Contains(line, v):
				used = true
				if !masked {
					t.Errorf("%q printed before it was masked: %q", v, line)
				}
			}
		}
		if !used {
			t.Errorf("%q never printed; the check proves nothing", v)
		}
	}
}

func TestDeployMasksPersonalValuesInGitHubActions(t *testing.T) {
	s := newSandbox(t, baseConfig+"AUTHORIZE_USERNAME=the-owner\n")
	s.env = append(s.env, "GITHUB_ACTIONS=true")
	out, err := s.run("", "deploy.sh")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	checkMasked(t, out, "me@example.org", "claude-0123456789abcdef", "example.org,friend@example.net",
		"friend@example.net", fakeURL)
}

func TestDeployDoesNotMaskOutsideGitHubActions(t *testing.T) {
	s := newSandbox(t, baseConfig)
	out, err := s.run("", "deploy.sh")
	if err != nil || strings.Contains(out, "::add-mask::") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func ciSandbox(t *testing.T, deployEnv string) (*sandbox, string) {
	t.Helper()
	s := newSandbox(t, "unused: ci-deploy.sh writes its own\n")
	tmp := t.TempDir()
	s.env = slices.DeleteFunc(s.env, func(e string) bool { return e == "YES=1" || strings.HasPrefix(e, "CONFIG=") })
	s.env = append(s.env, "GITHUB_ACTIONS=true", "RUNNER_TEMP="+tmp,
		"ACTIONS_ID_TOKEN_REQUEST_URL=https://token.actions.example/id?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN=request-token-0123456789",
		"GCP_WIF_PROVIDER="+wifProvider, "GCP_DEPLOY_SA="+deploySA, "DEPLOY_ENV="+deployEnv)
	return s, tmp
}

func TestCIDeploy(t *testing.T) {
	s, tmp := ciSandbox(t, cdConfig)
	s.env = append(s.env, "SKIP_GCLOUD_INSTALL=1")
	s.mark("service")
	s.markValue("baseurl", fakeURL)
	out, err := s.run("", "ci-deploy.sh")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	gcloud := s.calls("gcloud")
	if len(gcloud) == 0 || !containsAll(gcloud[0], "auth", "login") {
		t.Fatalf("first gcloud call is not the sign-in: %q", gcloud)
	}
	if len(s.calls("gcloud", "auth", "configure-docker", "europe-west1-docker.pkg.dev", "--quiet")) != 1 {
		t.Error("Docker not configured for Artifact Registry")
	}
	deploys := s.calls("gcloud", "run", "deploy")
	if len(deploys) != 1 || len(s.calls("gcloud", "run", "services", "list")) != 0 {
		t.Fatalf("not an UPDATE_ONLY deploy: %q", s.calls("gcloud", "run"))
	}
	checkDeployCallAccess(t, deploys[0], fakeURL, "")
	checkMasked(t, out, "me@example.org", "claude-0123456789abcdef", "friend@example.net", fakeURL)

	// The credential configuration: external account, impersonation, and
	// the request token only inside this 0600 file, never in an argument.
	path := filepath.Join(s.state, "credentials.json")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("credential file mode %v", fi.Mode().Perm())
	}
	var cred struct {
		Type, Audience   string
		TokenURL         string `json:"token_url"`
		SubjectTokenType string `json:"subject_token_type"`
		Source           struct {
			URL     string
			Headers map[string]string
			Format  struct {
				Type  string
				Field string `json:"subject_token_field_name"`
			}
		} `json:"credential_source"`
		Impersonation string `json:"service_account_impersonation_url"`
	}
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &cred); err != nil {
		t.Fatal(err)
	}
	if cred.Type != "external_account" || cred.Audience != "//iam.googleapis.com/"+wifProvider ||
		cred.TokenURL != "https://sts.googleapis.com/v1/token" || cred.SubjectTokenType != "urn:ietf:params:oauth:token-type:jwt" ||
		cred.Source.URL != "https://token.actions.example/id?api-version=2.0&audience="+url.QueryEscape("https://iam.googleapis.com/"+wifProvider) ||
		cred.Source.Headers["Authorization"] != "Bearer request-token-0123456789" ||
		cred.Source.Format.Type != "json" || cred.Source.Format.Field != "value" ||
		cred.Impersonation != "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"+deploySA+":generateAccessToken" {
		t.Errorf("credential configuration:\n%s", b)
	}
	for _, c := range s.calls("") {
		if strings.Contains(strings.Join(c, " "), "request-token") {
			t.Errorf("request token in argv: %q", c)
		}
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("work directory left behind: %v", left)
	}
}

// Without SKIP_GCLOUD_INSTALL the download must match the pinned SHA-256;
// the fake curl delivers something else.
func TestCIDeployVerifiesGcloudChecksum(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the pinned gcloud is for linux/amd64")
	}
	s, _ := ciSandbox(t, cdConfig)
	s.mark("service")
	out, err := s.run("", "ci-deploy.sh")
	if err == nil || !strings.Contains(out, "SHA-256 mismatch") {
		t.Fatalf("unverified download accepted: %v\n%s", err, out)
	}
	if n := len(s.calls("gcloud")) + len(s.calls("docker")); n != 0 {
		t.Errorf("%d gcloud/docker calls after a bad download", n)
	}
	if len(s.calls("curl", "https://storage.googleapis.com/cloud-sdk-release/google-cloud-cli-590.0.0-linux-x86_64.tar.gz")) != 1 {
		t.Error("not downloaded from the pinned URL")
	}
}

func TestCIDeployRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		drop, add []string
		want      string
	}{
		"outside actions":  {[]string{"GITHUB_ACTIONS"}, nil, "runs in GitHub Actions only"},
		"no id token":      {[]string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN"}, nil, "id-token: write"},
		"no config":        {[]string{"DEPLOY_ENV"}, nil, "DEPLOY_ENV is not set"},
		"bad provider":     {nil, []string{"GCP_WIF_PROVIDER=projects/x/providers/y"}, "GCP_WIF_PROVIDER must be"},
		"other account":    {nil, []string{"GCP_DEPLOY_SA=someone-else@test-project-1.iam.gserviceaccount.com"}, "GCP_DEPLOY_SA is not the deployer"},
		"secret in config": {nil, []string{"DEPLOY_ENV=" + cdConfig + "MAIL_PASSWORD=x\n"}, "MAIL_PASSWORD is a secret"},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := ciSandbox(t, cdConfig)
			s.env = slices.DeleteFunc(s.env, func(e string) bool {
				k, _, _ := strings.Cut(e, "=")
				return slices.Contains(tc.drop, k) || slices.ContainsFunc(tc.add, func(a string) bool { return strings.HasPrefix(a, k+"=") })
			})
			s.env = append(s.env, append(tc.add, "SKIP_GCLOUD_INSTALL=1")...)
			s.mark("service")
			out, err := s.run("", "ci-deploy.sh")
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("want error %q, got %v\n%s", tc.want, err, out)
			}
			if n := len(s.calls("")); n != 0 {
				t.Errorf("%d external calls despite the error", n)
			}
		})
	}
}

// The workflow and the provider's condition must agree on file, branch and
// environment, and the privileged job must run only first-party code.
func TestDeployWorkflowMatchesCondition(t *testing.T) {
	root, _ := filepath.Abs("..")
	wf, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "deploy.yml"))
	if err != nil {
		t.Fatal(err)
	}
	setup, _ := os.ReadFile(filepath.Join(root, "scripts", "gcp-github.sh"))
	ci, _ := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	for _, w := range []string{"WORKFLOW=.github/workflows/deploy.yml\n", "BRANCH=main\n", "ENVIRONMENT=production\n"} {
		if !strings.Contains(string(setup), w) {
			t.Errorf("gcp-github.sh lacks %q", w)
		}
	}
	for _, w := range []string{"    workflows: [ci]\n", "    branches: [main]\n", "github.ref == 'refs/heads/main'",
		"    environment: production\n", "      id-token: write\n", "\npermissions: {}\n", "cancel-in-progress: false",
		"github.event.workflow_run.event == 'push'", "github.event.workflow_run.head_sha == github.sha",
		"run: scripts/ci-deploy.sh\n"} {
		if !strings.Contains(string(wf), w) {
			t.Errorf("deploy.yml lacks %q", w)
		}
	}
	if !strings.Contains(string(ci), "\nname: ci\n") {
		t.Error("ci.yml is not named ci, so deploy.yml would never trigger")
	}
	for _, m := range regexp.MustCompile(`uses:\s*(\S+)`).FindAllStringSubmatch(string(wf), -1) {
		if !strings.HasPrefix(m[1], "actions/checkout@") {
			t.Errorf("third-party action in the deploy job: %s", m[1])
		}
	}
}
