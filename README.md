# AutoRed

Autonomous red-team copilot. Phase 1: Recon Agent.

## Install

```bash
uv sync
cp .env.example .env  # edit with your API keys
```

## Usage

```bash
# Run recon against a target (headless)
autored run --target 10.10.10.5 --roe roe-sandbox.yaml --no-tui

# Resume an interrupted engagement
autored resume <engagement_id>

# List engagements
autored engagements
```

## Development

```bash
uv run pytest                    # run tests
uv run pytest --cov=autored      # run with coverage
uv run ruff check autored tests  # lint
uv run ruff format autored tests # format
```

## E2E Tests

E2E tests run against live targets (HackTheBox). They're skipped by
default — set `AUTORED_E2E=1` to opt in.

To run the Phase 1 E2E test against HTB Lame (`10.10.10.5`):

```bash
# 1. Connect to HackTheBox VPN
sudo openvpn user.ovpn

# 2. Verify target is reachable
ping 10.10.10.5

# 3. Set env vars
export ANTHROPIC_API_KEY=sk-ant-...
export AUTORED_E2E=1

# 4. Run E2E test (use -s to see live findings)
uv run pytest tests/e2e/test_phase1_lame.py -v -s
```

Expected runtime: 5–10 minutes. The test passes if:

- nmap discovers ports 21 (FTP), 22 (SSH), and 445 (SMB)
- All tools (`naabu`, `httpx`, `nuclei`, `feroxbuster`, etc.) execute
  without error
- The Phase 1 graph reaches the `done` phase
- Final state has at least 1 host and 3 services

## Phase 2 E2E Test (Shocker)

Phase 2 adds the Vuln Agent (CVE correlation, exploit search, self-critique
loop, ranked attack hypotheses). The Phase 2 E2E test runs recon + vuln
against HTB Shocker (`10.10.10.56`) and asserts the Vuln Agent identifies
Shellshock (CVE-2014-6271).

```bash
# 1. Connect to HackTheBox VPN
sudo openvpn user.ovpn

# 2. Verify Shocker is reachable
ping 10.10.10.56

# 3. Set env vars
export ANTHROPIC_API_KEY=sk-ant-...
export DEEPSEEK_API_KEY=sk-...
export AUTORED_E2E=1

# 4. Run Phase 2 E2E test (use -s to see live findings + hypotheses)
uv run pytest tests/e2e/test_phase2_shocker.py -v -s
```

Expected runtime: 10–15 minutes. The test passes if:

- Recon discovers port 80 (Apache httpd 2.2.22) on Shocker
- All tools (`nmap`, `naabu`, `httpx`, `nuclei`, `feroxbuster`,
  `searchsploit`, etc.) execute without error
- The Vuln Agent produces at least 1 attack hypothesis
- At least one hypothesis references Shellshock (CVE-2014-6271)
- The Phase 2 graph reaches the `done` phase
