#!/bin/bash

# =============================================================================
# run_demo.sh — Catnip Games SOC Full Pipeline Demo Runner
# =============================================================================

# Executes the complete SOC automation pipeline in the correct order.
# Run this before the demonstration to reset the environment to a clean,
# known state with all cases, tasks, TTPs, and enrichment applied.

# USAGE:
#     chmod +x run_demo.sh
#     ./run_demo.sh

# WHAT IT DOES:
#     Step 1: Deletes old cases and generates 6 fresh Catnip Games incidents
#     Step 2: Injects investigation tasks based on category tags
#     Step 3: Maps MITRE ATT&CK TTPs based on category tags
#     Step 4: Runs MISP intelligence lookup on all observables
#     Step 5: Reminder to manually trigger GameThreat analyser in Cortex
#     Step 6: Runs writeback to push Cortex results back to TheHive

# REQUIREMENTS:
#     - TheHive running at http://192.168.56.200:9000
#     - Cortex running at http://192.168.56.200:9001
#     - MISP running at https://192.168.56.200
#     - Python 3 with requests, rich, urllib3 installed
#       (pip install -r requirements.txt)

# NOTE: After Step 3, pause and manually trigger the GameThreat analyser
#       on the observable 185.220.101.45 in Case #1 before running Step 5.
#       The writeback (Step 5) requires at least one completed Cortex job.

# =============================================================================


set -e  # Exit on error

SCRIPTS_DIR="$(cd "$(dirname "$0")/scripts" && pwd)"
LOG_FILE="/tmp/catnip-demo-$(date +%Y%m%d-%H%M%S).log"

# ── Colour output ─────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {

    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

}

print_step() {

    echo ""
    echo -e "${YELLOW}${BOLD}[ STEP $1 ]${NC} $2"
    echo -e "${YELLOW}─────────────────────────────────────────────────────────────────${NC}"

}

print_ok() {

    echo -e "${GREEN}  ✓  $1${NC}"

}

print_warn() {

    echo -e "${YELLOW}  ⚠  $1${NC}"

}

print_error() {

    echo -e "${RED}  ✗  $1${NC}"

}

pause_for_demo() {

    echo ""
    echo -e "${BOLD}  ┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}  │  DEMO PAUSE — complete the manual step above, then      │${NC}"
    echo -e "${BOLD}  │  press ENTER to continue the pipeline.                  │${NC}"
    echo -e "${BOLD}  └─────────────────────────────────────────────────────────┘${NC}"
    read -r -p "  Press ENTER to continue... "

}


# ── Pre-flight checks ─────────────────────────────────────────────────────────

print_header "CATNIP GAMES SOC — FULL PIPELINE DEMO RUNNER"

echo ""
echo -e "  ${BOLD}Log file:${NC} $LOG_FILE"
echo -e "  ${BOLD}Started:${NC}  $(date)"
echo ""

echo -e "${BOLD}Pre-flight checks...${NC}"


# Check TheHive is reachable
if curl -sf http://192.168.56.200:9000/api/status > /dev/null 2>&1; then
    print_ok "TheHive reachable at http://192.168.56.200:9000"
else
    print_error "TheHive not reachable. Start the stack first:"
    echo "         cd ~/catnip-soc && sudo docker compose up -d"
    echo "         sudo chmod 777 /tmp/cortex-jobs"
    exit 1
fi


# Check Cortex is reachable
if curl -sf http://192.168.56.200:9001/index.html > /dev/null 2>&1; then
    print_ok "Cortex reachable at http://192.168.56.200:9001"
else
    print_warn "Cortex not reachable — writeback step will be skipped"
    SKIP_WRITEBACK=true
fi


# Check Python is available
if command -v python3 &> /dev/null; then
    print_ok "Python 3 available: $(python3 --version)"
else
    print_error "Python 3 not found. Install with: sudo apt install python3"
    exit 1
fi


# Check scripts directory exists
if [ ! -d "$SCRIPTS_DIR" ]; then
    print_error "Scripts directory not found: $SCRIPTS_DIR"
    exit 1
fi


echo ""

# ── Step 1: Generate cases ────────────────────────────────────────────────────

print_step "1" "Generate fresh Catnip Games incident cases"
echo "  Deletes any existing matching cases and creates 6 new ones."
echo "  Each case has category tags, severity, TLP/PAP, and IOC observables."
echo ""


if python3 "$SCRIPTS_DIR/generate_cases.py" 2>&1 | tee -a "$LOG_FILE"; then
    print_ok "Cases generated successfully"
else
    print_error "generate_cases.py failed — check the log: $LOG_FILE"
    exit 1
fi


sleep 1


# ── Step 2: Add investigation tasks ──────────────────────────────────────────

print_step "2" "Inject investigation tasks based on category tags"
echo "  Reads each case's category tag and assigns the correct task list."
echo "  Duplicate-safe — safe to re-run without creating extra tasks."
echo ""

if python3 "$SCRIPTS_DIR/add_tasks.py" 2>&1 | tee -a "$LOG_FILE"; then
    print_ok "Tasks injected successfully"
else
    print_error "add_tasks.py failed — check the log: $LOG_FILE"
    exit 1
fi


sleep 1


# ── Step 3: Map MITRE ATT&CK TTPs ────────────────────────────────────────────

print_step "3" "Map MITRE ATT&CK TTPs based on category tags"
echo "  Adds ATT&CK technique IDs (T1110, T1566, etc.) to each case"
echo "  based on the incident category — no manual mapping required."
echo ""

if python3 "$SCRIPTS_DIR/tag_based_ttps.py" 2>&1 | tee -a "$LOG_FILE"; then
    print_ok "TTPs mapped successfully"
else
    print_error "tag_based_ttps.py failed — check the log: $LOG_FILE"
    exit 1
fi


sleep 1


# ── Step 4: MISP intelligence lookup ─────────────────────────────────────────

print_step "4" "Run MISP intelligence lookup on all observables"
echo "  Checks each case observable against the MISP threat intelligence"
echo "  platform. Adds misp:hit or misp:clean tags to each case."
echo ""

if python3 "$SCRIPTS_DIR/misp_lookup.py" 2>&1 | tee -a "$LOG_FILE"; then
    print_ok "MISP lookup completed"
else
    print_warn "misp_lookup.py had errors — check the log. Continuing..."
fi


sleep 1


# ── Manual step: Trigger Cortex analyser ─────────────────────────────────────

echo ""
print_step "5" "⚠  MANUAL STEP — Trigger GameThreat analyser in Cortex"
echo ""
echo -e "  ${BOLD}Do this now in TheHive:${NC}"
echo "  1. Open TheHive: http://192.168.56.200:9000"
echo "  2. Open Case #1: 'Suspicious login attempts on player accounts'"
echo "  3. Click the Observables tab"
echo "  4. Find observable: 185.220.101.45"
echo "  5. Click the analyser icon → select GameThreat → Run"
echo "  6. Wait for the job to show 'Success' (usually 10-15 seconds)"
echo ""
echo "  This observable is in the GameThreat blocklist and will return:"
echo "  → Risk: HIGH | Confidence: 95% | Reason: Tor exit node"
echo ""
echo "  You can also run it on other observables for additional demo depth."
echo ""

pause_for_demo

# ── Step 6: Writeback Cortex results to TheHive ───────────────────────────────

if [ "$SKIP_WRITEBACK" = true ]; then
    print_warn "Skipping writeback — Cortex was not reachable"
else
    print_step "6" "Write Cortex analyser results back to TheHive cases"
    echo "  Reads completed GameThreat jobs from Cortex."
    echo "  Updates TheHive: severity escalation, enrichment tags, timeline entries."
    echo ""

    if python3 "$SCRIPTS_DIR/thehive_writeback.py" 2>&1 | tee -a "$LOG_FILE"; then
        print_ok "Writeback completed"
    else
        print_warn "thehive_writeback.py had errors — check the log. Continuing..."
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
