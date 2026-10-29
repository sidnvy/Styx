//! Terminal presentation only. Secrets never enter this module.
use std::io::{self, BufRead, IsTerminal, Read, Write};

pub fn terminal() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}
pub fn line(question: &str, default: Option<&str>) -> Result<String, &'static str> {
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
        .map_err(|_| "setup_input_unavailable")?
        == 0
    {
        return Err("setup_input_closed");
    }
    if value.len() > 65536 {
        return Err("setup_input_too_large");
    }
    let value = value.trim();
    if value.is_empty() {
        Ok(default.unwrap_or("").to_owned())
    } else {
        Ok(value.to_owned())
    }
}
pub fn confirm(question: &str) -> Result<bool, &'static str> {
    confirm_default(question, false)
}
pub fn confirm_default(question: &str, yes: bool) -> Result<bool, &'static str> {
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
