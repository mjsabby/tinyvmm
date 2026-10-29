use anyhow::{Result, bail};
use std::{ffi::OsString, io::IsTerminal, sync::Arc};

pub fn run(args: &[OsString]) -> Result<()> {
    let args: Vec<String> = args
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    tokio::runtime::Runtime::new()?.block_on(async {
        let interactive = args.is_empty() && std::io::stdin().is_terminal();
        let mut shell = brush_core::Shell::builder()
            .builtins(brush_builtins::default_builtins(
                brush_builtins::BuiltinSet::BashMode,
            ))
            .interactive(interactive)
            .shell_name("/bin/sh".into())
            .build()
            .await?;
        let code = match args.first().map(String::as_str) {
            Some("-c") => {
                let command = args
                    .get(1)
                    .ok_or_else(|| anyhow::anyhow!("-c requires a command"))?;
                u8::from(shell.run_dash_c_command(command).await?.exit_code)
            }
            Some(option) if option.starts_with('-') => bail!("unsupported shell option {option}"),
            Some(script) => u8::from(
                shell
                    .run_script(script, args[1..].iter().cloned())
                    .await?
                    .exit_code,
            ),
            None => {
                let shell = Arc::new(tokio::sync::Mutex::new(shell));
                let mut input = brush_interactive::BasicInputBackend;
                brush_interactive::InteractiveShell::new(
                    &shell,
                    &mut input,
                    &brush_interactive::InteractiveOptions::default(),
                )?
                .run_interactively()
                .await?;
                shell.lock().await.last_exit_status()
            }
        };
        std::process::exit(i32::from(code));
    })
}
