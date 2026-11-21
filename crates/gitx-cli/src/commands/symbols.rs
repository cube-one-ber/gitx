use anyhow::{Context, Result};
use gitx_merge::extract_ast_symbols;
use std::fs;
use std::path::PathBuf;

pub fn cmd_symbols(path: PathBuf, json: bool) -> Result<()> {
    let source = fs::read_to_string(&path)
        .with_context(|| format!("failed to read source file '{}'", path.display()))?;
    let path_str = path.to_string_lossy();
    let symbols = extract_ast_symbols(&path_str, &source);

    if json {
        println!("{}", serde_json::to_string_pretty(&symbols)?);
        return Ok(());
    }

    if symbols.is_empty() {
        println!("No symbols found in {}", path.display());
        return Ok(());
    }

    for sym in &symbols {
        println!(
            "{:<10} {}  L{}-L{}",
            sym.kind, sym.name, sym.line_start, sym.line_end
        );
    }
    Ok(())
}
