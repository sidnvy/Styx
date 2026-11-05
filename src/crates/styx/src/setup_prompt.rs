//! Terminal presentation only. Secrets never enter this module.
use console::{Style, Term};
use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::{
    io::{self, BufRead, IsTerminal, Read, Write},
    sync::OnceLock,
    time::Duration,
};

static PROGRESS: OnceLock<MultiProgress> = OnceLock::new();

pub fn terminal() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}
pub fn enhanced() -> bool {
    terminal()
        && io::stderr().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").is_ok_and(|value| value != "dumb")
}
fn display(line: &str) {
    if let Some(progress) = PROGRESS.get() {
        progress.suspend(|| eprintln!("{line}"));
    } else {
        eprintln!("{line}");
    }
}
pub fn section(title: &str) {
    if enhanced() {
        display(&format!("\n{}", Style::new().cyan().bold().apply_to(title)));
    } else {
        println!("\n{title}");
    }
}
pub fn info(message: &str) {
    if enhanced() {
        display(&format!("{} {message}", Style::new().cyan().apply_to("•")));
    } else {
        println!("{message}");
    }
}
pub fn success(message: &str) {
    if enhanced() {
        display(&format!("{} {message}", Style::new().green().apply_to("✓")));
    } else {
        println!("{message}");
    }
}
pub fn failure(code: &str, hint: Option<&str>, unknown: bool) {
    if code == "setup_cancelled" {
        display(&format!(
            "\n{}",
            Style::new().yellow().bold().apply_to("Setup cancelled")
        ));
        display("No new changes were applied.");
        return;
    }
    display(&format!(
        "\n{} {}",
        Style::new().red().bold().apply_to("Setup stopped"),
        Style::new().dim().apply_to(format!("({code})"))
    ));
    if let Some(hint) = hint {
        display(hint);
    }
    if unknown {
        display(
            "The original outcome is unknown. Keep the saved configuration and receipts; inspect the original operation before taking another action.",
        );
    } else {
        display(
            "Saved setup progress is kept. Resume this same configuration after resolving the error.",
        );
    }
}
// Dialoguer propagates terminal read failures. Restore cursor visibility on
// every return path as well as the library's ordinary successful completion.
struct Cursor(Term);
impl Drop for Cursor {
    fn drop(&mut self) {
        let _ = self.0.show_cursor();
        let _ = self.0.flush();
    }
}
fn input<T>(read: impl FnOnce(&Term) -> dialoguer::Result<T>) -> Result<T, &'static str> {
    let cursor = Cursor(Term::stderr());
    read(&cursor.0).map_err(|_| "setup_input_closed")
}
pub fn line(question: &str, default: Option<&str>) -> Result<String, &'static str> {
    if enhanced() {
        let theme = ColorfulTheme::default();
        let mut input = Input::<String>::with_theme(&theme)
            .with_prompt(question)
            .allow_empty(true);
        if let Some(value) = default {
            input = input.default(value.to_owned());
        }
        let value = self::input(|term| input.interact_text_on(term))?;
        if value.len() > 65536 {
            return Err("setup_input_too_large");
        }
        return Ok(value.trim().to_owned());
    }
    print!("{question}");
    if let Some(value) = default {
        print!(" [{value}]");
    }
    print!(": ");
    io::stdout()
        .flush()
        .map_err(|_| "setup_output_unavailable")?;
    let mut value = String::new();
    if io::stdin()
        .lock()
        .take(65537)
        .read_line(&mut value)
        .map_err(|_| "setup_input_closed")?
        == 0
    {
        return Err("setup_input_closed");
    }
    if value.len() > 65536 {
        return Err("setup_input_too_large");
    }
    let value = value.trim();
    Ok(if value.is_empty() {
        default.unwrap_or("")
    } else {
        value
    }
    .to_owned())
}
pub fn select(question: &str, choices: &[&str], default: usize) -> Result<usize, &'static str> {
    if enhanced() {
        return input(|term| {
            Select::with_theme(&ColorfulTheme::default())
                .with_prompt(question)
                .items(choices)
                .default(default)
                .interact_on(term)
        });
    }
    for (index, choice) in choices.iter().enumerate() {
        println!("{}. {choice}", index + 1);
    }
    let value = line(question, Some(&(default + 1).to_string()))?;
    value
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .filter(|n| *n < choices.len())
        .ok_or("setup_role_invalid")
}
pub fn networks(choices: &[String]) -> Result<Vec<usize>, &'static str> {
    if choices.is_empty() {
        info("No private networks were found; this Gateway will accept local connections only.");
        return Ok(Vec::new());
    }
    if enhanced() {
        loop {
            info(
                "Space selects a network; Enter continues. Select up to four, or leave all empty for local access only.",
            );
            let selected = input(|term| {
                MultiSelect::with_theme(&ColorfulTheme::default())
                    .with_prompt("Networks other computers can use")
                    .items(choices)
                    .interact_on(term)
            })?;
            if selected.len() <= 4 {
                return Ok(selected);
            }
            info("Select no more than four networks.");
        }
    }
    for (index, choice) in choices.iter().enumerate() {
        println!("{}. {choice}", index + 1);
    }
    let value = line(
        "Network numbers, separated by commas (empty for none)",
        None,
    )?;
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let result = value
        .split(',')
        .map(|part| {
            part.trim()
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .filter(|n| *n < choices.len())
                .ok_or("setup_network_choices_invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if result.len() > 4 {
        return Err("setup_network_choices_invalid");
    }
    Ok(result)
}
pub fn confirm(question: &str) -> Result<bool, &'static str> {
    confirm_default(question, false)
}
pub fn confirm_default(question: &str, yes: bool) -> Result<bool, &'static str> {
    if enhanced() {
        return input(|term| {
            Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(question)
                .default(yes)
                .wait_for_newline(true)
                .interact_on(term)
        });
    }
    loop {
        match line(
            &format!("{question} [{}]", if yes { "Y/n" } else { "y/N" }),
            None,
        )?
        .to_lowercase()
        .as_str()
        {
            "y" | "yes" => return Ok(true),
            "" => return Ok(yes),
            "n" | "no" => return Ok(false),
            _ => println!("Enter yes or no."),
        }
    }
}
/// Dropping a pending indicator clears it; only an observed result may finish it.
pub struct Waiting(Option<ProgressBar>);
impl Waiting {
    pub fn finish(self, message: &str) {
        if let Some(progress) = &self.0 {
            progress.finish_and_clear();
        }
        success(message);
    }
}
impl Drop for Waiting {
    fn drop(&mut self) {
        if let Some(progress) = &self.0 {
            progress.finish_and_clear();
        }
    }
}
pub fn waiting(message: &'static str) -> Waiting {
    if !enhanced() {
        println!("{message}");
        return Waiting(None);
    }
    let progress = PROGRESS
        .get_or_init(MultiProgress::new)
        .add(ProgressBar::new_spinner());
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg} [{elapsed_precise}]")
            .expect("fixed terminal progress template"),
    );
    progress.set_message(message);
    progress.enable_steady_tick(Duration::from_millis(100));
    Waiting(Some(progress))
}
