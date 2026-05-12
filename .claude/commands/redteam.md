# Red-Team Agent

Run the llm-redteam framework against the LangGraph agent in the current project.

## Setup check

First, locate the llm-redteam project by running:
```bash
echo "${LLM_REDTEAM_PATH:-not set}"
```

If `LLM_REDTEAM_PATH` is not set, search for it:
```bash
find ~ -maxdepth 4 -name "main.py" -path "*/llm-redteam/*" 2>/dev/null | head -1
```

If still not found, tell the user:
> "I can't find the llm-redteam project. Set the path in your shell profile:
> `export LLM_REDTEAM_PATH=/path/to/llm-redteam`
> Then restart Claude Code and try again."

Use the found path as `$REDTEAM_PATH` for all subsequent commands.

## Steps

### 1. Detect the current agent

Check if the current working directory has a `langgraph.json`:
```bash
cat langgraph.json 2>/dev/null
```

Extract the graph name (assistant ID) from it.

If no `langgraph.json` exists, tell the user:
> "I don't see a LangGraph project here. Navigate to your agent project directory and try again."

### 2. Check if the dev server is running

```bash
curl -s http://localhost:2024/ok 2>/dev/null || curl -s http://localhost:2025/ok 2>/dev/null
```

If no server responds:
> "Your LangGraph dev server is not running. Start it with:
> `uv run langgraph dev --port 2024`
> Then run /redteam again."

Stop here if not running.

### 3. Ask the user which mode

Ask: "Quick mode (1 run, ~5 min, cheaper) or Full mode (3 runs, ~15 min, more reliable)?"
- Quick → `--runs 1`
- Full  → `--runs 3`

### 4. Run the framework

```bash
cd $REDTEAM_PATH && uv run python main.py \
  --env-file <current_project_absolute_path>/.env \
  --agent-url http://localhost:<detected_port> \
  --assistant-id <graph_name> \
  --runs <1_or_3>
```

Show output as it runs.

### 5. Read the latest report

```bash
ls -t $REDTEAM_PATH/reports/*.json 2>/dev/null | head -1
```

Read that file.

### 6. Summarize findings

**No vulnerabilities:**
> "✓ No vulnerabilities confirmed across all [N] attacks."

**Vulnerabilities found** — summarize by severity:
- Overall risk level
- For each finding: name, category, what happened, judge's reasoning
- Highlight CRITICAL first (especially unintended tool calls)

### 7. Offer to apply patches

> "I have prompt patches for the affected categories. Apply them to your system prompt?"

If yes:
- Find the system prompt file (check `prompts/` or `.md` files in the project)
- Show what will change and ask for confirmation before editing
- Append only the patches relevant to confirmed vulnerabilities

If no:
- Print the patches as text for manual application

### 8. Done

Tell the user the report was saved to:
`$REDTEAM_PATH/reports/report_<timestamp>.json`
