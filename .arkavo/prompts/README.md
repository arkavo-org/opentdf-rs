# Custom Prompts Directory

Place your custom prompt overrides here to replace the built-in prompts.

## Available Prompts to Override

- `chat_system.prompt.md` - System prompt for chat command
- `terminal_system.prompt.md` - System prompt for terminal UI
- `agent_system.prompt.md` - System prompt for agents
- `agents_md.prompt.md` - Template for generating AGENTS.md files

## How to Override

1. Copy the prompt file from `assets/prompts/` to this directory
2. Modify it as needed
3. The custom version will be used automatically

Example:
```bash
cp ../../assets/prompts/chat_system.prompt.md ./chat_system.prompt.md
# Edit chat_system.prompt.md with your customizations
```

The arkavo CLI will automatically detect and use your custom prompts.
