use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::DefaultTerminal;

pub fn run() -> Result<()> {
    ratatui::run(|terminal: &mut DefaultTerminal| -> Result<()> {
        loop {
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    let block = Block::default()
                        .title(" networker ")
                        .borders(Borders::ALL);
                    let inner = block.inner(area);
                    frame.render_widget(block, area);
                    frame.render_widget(
                        Paragraph::new(
                            "Interactive mode (no subcommand).\n\
                             Run `networker scan` from another terminal for a one-shot scan.\n\
                             \n\
                             Press q to quit.",
                        ),
                        inner,
                    );
                })
                .context("terminal draw")?;

            match event::read().context("read keyboard event")? {
                Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(()),
                    _ => {}
                },
                _ => {}
            }
        }
    })
    .context("ratatui run")
}
