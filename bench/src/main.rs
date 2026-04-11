mod helpers;

use {
    anchor_bench::{generate_flamegraph_from_trace, BenchContext, BenchInstruction},
    anyhow::{Context, Result},
    helpers::*,
    solana_signer::Signer,
    std::path::{Path, PathBuf},
    tempfile::TempDir,
};


fn case_create_wallet(kind: ProgramKind) -> impl Fn(&mut BenchContext) -> Result<BenchInstruction> {
    move |ctx: &mut BenchContext| {
        let setup = WalletSetup::default();
        ctx.airdrop(&setup.creator.pubkey(), 10_000_000_000)?;

        let data = build_create_wallet_data(
            kind,
            1, 1, 0,
            &setup.wallet_name,
            &[ed25519_pubkey(&setup.proposer)],
            &[ed25519_pubkey(&setup.approver)],
        );
        let metas = create_wallet_metas(setup.creator.pubkey(), &setup.wallet_name);
        Ok(BenchInstruction::new(data, metas).with_signer(setup.creator.insecure_clone()))
    }
}

fn case_propose(kind: ProgramKind) -> impl Fn(&mut BenchContext) -> Result<BenchInstruction> {
    move |ctx: &mut BenchContext| {
        let setup = setup_wallet(ctx, kind)?;

        let target_intent_index = 2u8;
        let remove_intent = intent_pda(&setup.wallet, 1);
        let proposal_index: u64 = 0;
        let params_data = vec![target_intent_index];

        let msg = remove_intent_msg(
            "propose", DEFAULT_EXPIRY, setup.wallet_name_str(),
            proposal_index, target_intent_index,
        );
        let signature = sign_message(&setup.proposer, &msg);
        let metas = propose_metas(setup.creator.pubkey(), setup.wallet, remove_intent, proposal_index);
        let data = build_propose_data(
            kind, proposal_index, DEFAULT_EXPIRY,
            &ed25519_pubkey(&setup.proposer), &signature, &params_data,
        );
        Ok(BenchInstruction::new(data, metas).with_signer(setup.creator.insecure_clone()))
    }
}

fn case_approve(kind: ProgramKind) -> impl Fn(&mut BenchContext) -> Result<BenchInstruction> {
    move |ctx: &mut BenchContext| {
        let setup = setup_wallet(ctx, kind)?;
        let target_intent_index = 2u8;
        let (intent, proposal, _pd) = setup_proposed_remove_intent(ctx, kind, &setup, target_intent_index)?;

        let proposal_index: u64 = 0;
        let msg = remove_intent_msg(
            "approve", DEFAULT_EXPIRY, setup.wallet_name_str(),
            proposal_index, target_intent_index,
        );
        let signature = sign_message(&setup.approver, &msg);
        let metas = approve_metas(setup.wallet, intent, proposal);
        let data = build_approve_data(kind, DEFAULT_EXPIRY, 0, &signature);
        Ok(BenchInstruction::new(data, metas))
    }
}

fn case_cancel(kind: ProgramKind) -> impl Fn(&mut BenchContext) -> Result<BenchInstruction> {
    move |ctx: &mut BenchContext| {
        let setup = setup_wallet(ctx, kind)?;
        let target_intent_index = 2u8;
        let (intent, proposal, _pd) = setup_proposed_remove_intent(ctx, kind, &setup, target_intent_index)?;

        let proposal_index: u64 = 0;
        let msg = remove_intent_msg(
            "cancel", DEFAULT_EXPIRY, setup.wallet_name_str(),
            proposal_index, target_intent_index,
        );
        let signature = sign_message(&setup.approver, &msg);
        let metas = cancel_metas(setup.wallet, intent, proposal);
        let data = build_cancel_data(kind, DEFAULT_EXPIRY, 0, &signature);
        Ok(BenchInstruction::new(data, metas))
    }
}

fn case_execute(kind: ProgramKind) -> impl Fn(&mut BenchContext) -> Result<BenchInstruction> {
    move |ctx: &mut BenchContext| {
        let setup = setup_wallet(ctx, kind)?;
        let target_intent_index = 2u8;
        let (intent, proposal, _pd) = setup_proposed_remove_intent(ctx, kind, &setup, target_intent_index)?;
        setup_approved(ctx, kind, &setup, intent, proposal, target_intent_index)?;

        let target_intent = intent_pda(&setup.wallet, target_intent_index);
        let remaining = vec![solana_instruction::AccountMeta::new(target_intent, false)];
        let metas = execute_metas(setup.wallet, intent, proposal, remaining);
        let data = build_execute_data(kind);
        Ok(BenchInstruction::new(data, metas))
    }
}

fn case_cleanup(kind: ProgramKind) -> impl Fn(&mut BenchContext) -> Result<BenchInstruction> {
    move |ctx: &mut BenchContext| {
        let setup = setup_wallet(ctx, kind)?;
        let target_intent_index = 2u8;
        let (intent, proposal, _pd) = setup_proposed_remove_intent(ctx, kind, &setup, target_intent_index)?;
        setup_approved(ctx, kind, &setup, intent, proposal, target_intent_index)?;
        setup_executed_remove(ctx, kind, &setup, intent, proposal, target_intent_index)?;

        let acct_before = ctx.svm_mut().get_account(&proposal);
        if let Some(a) = &acct_before {
            assert!(a.lamports > 0, "proposal should have lamports before cleanup");
            assert!(!a.data.is_empty(), "proposal should have data before cleanup");
        }

        let metas = cleanup_metas(proposal, setup.creator.pubkey());
        let data = build_cleanup_data(kind);
        Ok(BenchInstruction::new(data, metas))
    }
}

struct Results {
    anchor: Vec<(&'static str, u64)>,
    quasar: Vec<(&'static str, u64)>,
}

impl Results {
    fn new() -> Self {
        Self { anchor: vec![], quasar: vec![] }
    }

    fn print(&self, anchor_size: u64, quasar_size: u64) {
        println!("\n=== Results ===\n");
        println!("{:<20}  {:>12}  {:>12}  {:>10}", "Metric", "Anchor v2", "Quasar", "Δ");
        println!("{}", "-".repeat(62));

        let size_pct = (quasar_size as f64 - anchor_size as f64) / anchor_size as f64 * 100.0;
        let fmt_bytes = |b: u64| {
            if b >= 1024 { format!("{:.1} KB", b as f64 / 1024.0) } else { format!("{b} B") }
        };
        println!(
            "{:<20}  {:>12}  {:>12}  {:>+9.1}%",
            "binary_size",
            fmt_bytes(anchor_size),
            fmt_bytes(quasar_size),
            size_pct,
        );
        println!("{}", "-".repeat(62));

        for (name, anchor_cu) in self.anchor.iter() {
            let quasar_cu = self.quasar.iter().find(|(n, _)| n == name).map(|(_, cu)| *cu);
            match quasar_cu {
                Some(q_cu) => {
                    let pct = (q_cu as f64 - *anchor_cu as f64) / *anchor_cu as f64 * 100.0;
                    println!(
                        "{name:<20}  {anchor_cu:>9} CU  {q_cu:>9} CU  {pct:>+9.1}%"
                    );
                }
                None => {
                    println!("{name:<20}  {anchor_cu:>9} CU  {:>12}  {:>10}", "N/A*", "—");
                }
            }
        }

        println!();
        println!("* Quasar cleanup_proposal fails under LiteSVM 0.10 with UnbalancedInstruction.");
        println!("  Quasar's manual close() sequence (zero disc → transfer lamports → assign →");
        println!("  resize) is semantically valid on real Solana but triggers LiteSVM's");
        println!("  stricter intermediate-state validation. Works in QuasarSvm test harness.");
    }
}

fn run_case(
    label: &'static str,
    path: &Path,
    case: impl Fn(&mut BenchContext) -> Result<BenchInstruction>,
) -> Option<u64> {
    print!("  {label:<20} ");
    let result = (|| -> Result<(u64, Vec<String>)> {
        let mut ctx = BenchContext::new(path, program_id())?;
        let instruction = case(&mut ctx)?;
        let meta = ctx.execute(instruction)?;
        Ok((meta.compute_units_consumed, meta.logs))
    })();
    match result {
        Ok((cu, logs)) => {
            println!("{cu} CU");
            if std::env::var("BENCH_VERBOSE").is_ok() {
                for log in &logs {
                    println!("      {log}");
                }
            }
            Some(cu)
        }
        Err(e) => {
            println!("FAILED: {e:#}");
            None
        }
    }
}

fn run_case_flamegraph(
    label: &str,
    program_label: &str,
    so_path: &Path,
    output_dir: &Path,
    case: impl Fn(&mut BenchContext) -> Result<BenchInstruction>,
) -> Result<PathBuf> {
    let trace_dir = TempDir::new().context("failed to create trace dir")?;
    std::env::set_var("SBF_TRACE_DIR", trace_dir.path());

    let result = (|| -> Result<()> {
        let mut ctx = BenchContext::new_with_tracing(so_path, program_id())?;
        let instruction = case(&mut ctx)?;

        // Clear setup traces so only the benchmarked instruction is measured.
        for entry in std::fs::read_dir(trace_dir.path())? {
            let _ = std::fs::remove_file(entry?.path());
        }

        ctx.execute(instruction)?;
        Ok(())
    })();
    std::env::remove_var("SBF_TRACE_DIR");
    result?;

    std::fs::create_dir_all(output_dir)?;
    let svg_name = format!("{program_label}_{label}.svg");
    let svg_path = output_dir.join(&svg_name);
    generate_flamegraph_from_trace(label, so_path, trace_dir.path(), &svg_path, None)
        .with_context(|| format!("flamegraph generation failed for {svg_name}"))?;
    Ok(svg_path)
}

fn binary_size(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}

fn main() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let positional: Vec<&String> = raw_args.iter().filter(|a| !a.starts_with("--")).collect();
    let anchor_path = positional
        .first()
        .expect("usage: clear-msig-bench <anchor.so> <quasar.so>");
    let quasar_path = positional
        .get(1)
        .expect("usage: clear-msig-bench <anchor.so> <quasar.so>");

    let anchor_path = Path::new(anchor_path);
    let quasar_path = Path::new(quasar_path);

    // Binary size
    let anchor_size = binary_size(anchor_path)?;
    let quasar_size = binary_size(quasar_path)?;

    let mut results = Results::new();

    println!("=== Anchor v2 ===");
    if let Some(cu) = run_case("create_wallet", anchor_path, case_create_wallet(ProgramKind::AnchorV2)) {
        results.anchor.push(("create_wallet", cu));
    }
    if let Some(cu) = run_case("propose", anchor_path, case_propose(ProgramKind::AnchorV2)) {
        results.anchor.push(("propose", cu));
    }
    if let Some(cu) = run_case("approve", anchor_path, case_approve(ProgramKind::AnchorV2)) {
        results.anchor.push(("approve", cu));
    }
    if let Some(cu) = run_case("cancel", anchor_path, case_cancel(ProgramKind::AnchorV2)) {
        results.anchor.push(("cancel", cu));
    }
    if let Some(cu) = run_case("execute", anchor_path, case_execute(ProgramKind::AnchorV2)) {
        results.anchor.push(("execute", cu));
    }
    if let Some(cu) = run_case("cleanup_proposal", anchor_path, case_cleanup(ProgramKind::AnchorV2)) {
        results.anchor.push(("cleanup_proposal", cu));
    }

    println!("\n=== Quasar ===");
    if let Some(cu) = run_case("create_wallet", quasar_path, case_create_wallet(ProgramKind::Quasar)) {
        results.quasar.push(("create_wallet", cu));
    }
    if let Some(cu) = run_case("propose", quasar_path, case_propose(ProgramKind::Quasar)) {
        results.quasar.push(("propose", cu));
    }
    if let Some(cu) = run_case("approve", quasar_path, case_approve(ProgramKind::Quasar)) {
        results.quasar.push(("approve", cu));
    }
    if let Some(cu) = run_case("cancel", quasar_path, case_cancel(ProgramKind::Quasar)) {
        results.quasar.push(("cancel", cu));
    }
    if let Some(cu) = run_case("execute", quasar_path, case_execute(ProgramKind::Quasar)) {
        results.quasar.push(("execute", cu));
    }
    if let Some(cu) = run_case("cleanup_proposal", quasar_path, case_cleanup(ProgramKind::Quasar)) {
        results.quasar.push(("cleanup_proposal", cu));
    }

    results.print(anchor_size, quasar_size);

    println!("\n=== Generating flamegraphs ===");
    let out_dir = std::env::current_dir()?.join("flamegraphs");
    println!("  output dir: {}", out_dir.display());

    let mut anchor_flames: Vec<(&str, Option<PathBuf>)> = Vec::new();
    let anchor_cases: Vec<(&str, Box<dyn Fn(&mut BenchContext) -> Result<BenchInstruction>>)> = vec![
        ("create_wallet", Box::new(case_create_wallet(ProgramKind::AnchorV2))),
        ("propose", Box::new(case_propose(ProgramKind::AnchorV2))),
        ("approve", Box::new(case_approve(ProgramKind::AnchorV2))),
        ("cancel", Box::new(case_cancel(ProgramKind::AnchorV2))),
        ("execute", Box::new(case_execute(ProgramKind::AnchorV2))),
        ("cleanup_proposal", Box::new(case_cleanup(ProgramKind::AnchorV2))),
    ];
    for (label, case) in anchor_cases {
        match run_case_flamegraph(label, "anchor_v2", anchor_path, &out_dir, |ctx| case(ctx)) {
            Ok(path) => {
                println!("  anchor_v2  {label:<20} {}", path.display());
                anchor_flames.push((label, Some(path)));
            }
            Err(e) => {
                println!("  anchor_v2  {label:<20} FAILED: {e:#}");
                anchor_flames.push((label, None));
            }
        }
    }

    let mut quasar_flames: Vec<(&str, Option<PathBuf>)> = Vec::new();
    let quasar_cases: Vec<(&str, Box<dyn Fn(&mut BenchContext) -> Result<BenchInstruction>>)> = vec![
        ("create_wallet", Box::new(case_create_wallet(ProgramKind::Quasar))),
        ("propose", Box::new(case_propose(ProgramKind::Quasar))),
        ("approve", Box::new(case_approve(ProgramKind::Quasar))),
        ("cancel", Box::new(case_cancel(ProgramKind::Quasar))),
        ("execute", Box::new(case_execute(ProgramKind::Quasar))),
        ("cleanup_proposal", Box::new(case_cleanup(ProgramKind::Quasar))),
    ];
    for (label, case) in quasar_cases {
        match run_case_flamegraph(label, "quasar", quasar_path, &out_dir, |ctx| case(ctx)) {
            Ok(path) => {
                println!("  quasar     {label:<20} {}", path.display());
                quasar_flames.push((label, Some(path)));
            }
            Err(e) => {
                println!("  quasar     {label:<20} FAILED: {e:#}");
                quasar_flames.push((label, None));
            }
        }
    }

    let report_path = std::env::current_dir()?.join("index.html");
    let html = build_html_report(
        &results,
        anchor_size,
        quasar_size,
        &anchor_flames,
        &quasar_flames,
    );
    std::fs::write(&report_path, html).context("failed to write index.html")?;
    println!("\nHTML report: {}", report_path.display());

    Ok(())
}

fn build_html_report(
    results: &Results,
    anchor_size: u64,
    quasar_size: u64,
    anchor_flames: &[(&str, Option<PathBuf>)],
    quasar_flames: &[(&str, Option<PathBuf>)],
) -> String {
    let mut s = String::with_capacity(8192);
    s.push_str(HTML_HEAD);

    s.push_str("<h1>clear-msig: anchor v2 vs quasar</h1>\n");
    s.push_str("<div class=\"meta\">cargo build-sbf · platform-tools v1.52 · same toolchain for both programs</div>\n\n");

    s.push_str("<h2>Results</h2>\n");
    s.push_str("<table>\n<thead><tr>");
    s.push_str("<th class=\"l\">Metric</th>");
    s.push_str("<th>Anchor v2</th>");
    s.push_str("<th>Quasar</th>");
    s.push_str("<th>Δ</th>");
    s.push_str("</tr></thead>\n<tbody>\n");

    {
        let pct = (quasar_size as f64 - anchor_size as f64) / anchor_size as f64 * 100.0;
        let cls = if pct >= 0.0 { "loss" } else { "win" };
        s.push_str(&format!(
            "<tr><td class=\"l\">binary_size</td><td>{}</td><td>{}</td><td class=\"{cls}\">{:+.1}%</td></tr>\n",
            fmt_bytes(anchor_size),
            fmt_bytes(quasar_size),
            pct,
        ));
    }

    for (name, anchor_cu) in results.anchor.iter() {
        let quasar_cu = results.quasar.iter().find(|(n, _)| n == name).map(|(_, cu)| *cu);
        match quasar_cu {
            Some(q) => {
                let pct = (q as f64 - *anchor_cu as f64) / *anchor_cu as f64 * 100.0;
                let cls = if pct >= 0.0 { "loss" } else { "win" };
                s.push_str(&format!(
                    "<tr><td class=\"l\">{name}</td><td>{anchor_cu} CU</td><td>{q} CU</td><td class=\"{cls}\">{:+.1}%</td></tr>\n",
                    pct,
                ));
            }
            None => {
                s.push_str(&format!(
                    "<tr><td class=\"l\">{name}</td><td>{anchor_cu} CU</td><td class=\"na\">N/A<sup>*</sup></td><td class=\"na\">—</td></tr>\n"
                ));
            }
        }
    }

    s.push_str("</tbody>\n</table>\n");
    s.push_str("<p class=\"note\"><sup>*</sup> Quasar cleanup_proposal fails under LiteSVM 0.10 with <code>UnbalancedInstruction</code>. Quasar's manual close() sequence is semantically valid on real Solana but trips LiteSVM's stricter intermediate-state validation.</p>\n");

    s.push_str("\n<h2>Flamegraphs</h2>\n");
    s.push_str("<p class=\"note\">Click any SVG to open it in a new tab for interactive zoom. Widths are proportional to reachable CU — values beside each label are the top-level totals.</p>\n");

    let labels = ["create_wallet", "propose", "approve", "cancel", "execute", "cleanup_proposal"];
    for label in labels {
        let anchor_cu = results.anchor.iter().find(|(n, _)| *n == label).map(|(_, cu)| *cu);
        let quasar_cu = results.quasar.iter().find(|(n, _)| *n == label).map(|(_, cu)| *cu);
        let anchor_path = anchor_flames.iter().find(|(n, _)| *n == label).and_then(|(_, p)| p.as_ref());
        let quasar_path = quasar_flames.iter().find(|(n, _)| *n == label).and_then(|(_, p)| p.as_ref());

        s.push_str(&format!("<h3>{label}</h3>\n"));
        s.push_str("<div class=\"flame-grid\">\n");

        s.push_str("<div class=\"flame\">\n");
        s.push_str(&format!(
            "<div class=\"flame-label\">anchor v2{}</div>\n",
            anchor_cu.map(|c| format!(" · {c} CU")).unwrap_or_default(),
        ));
        if let Some(p) = anchor_path {
            let rel = relpath(p);
            s.push_str(&format!(
                "<a href=\"{rel}\" target=\"_blank\"><img src=\"{rel}\" alt=\"{rel}\"></a>\n"
            ));
        } else {
            s.push_str("<div class=\"flame-miss\">not generated</div>\n");
        }
        s.push_str("</div>\n");

        s.push_str("<div class=\"flame\">\n");
        s.push_str(&format!(
            "<div class=\"flame-label\">quasar{}</div>\n",
            quasar_cu.map(|c| format!(" · {c} CU")).unwrap_or_default(),
        ));
        if let Some(p) = quasar_path {
            let rel = relpath(p);
            s.push_str(&format!(
                "<a href=\"{rel}\" target=\"_blank\"><img src=\"{rel}\" alt=\"{rel}\"></a>\n"
            ));
        } else {
            s.push_str("<div class=\"flame-miss\">not generated</div>\n");
        }
        s.push_str("</div>\n");

        s.push_str("</div>\n");
    }

    s.push_str("\n</body>\n</html>\n");
    s
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

fn relpath(p: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(rel) = p.strip_prefix(&cwd) {
            return rel.to_string_lossy().into_owned();
        }
    }
    p.to_string_lossy().into_owned()
}

const HTML_HEAD: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>clear-msig: anchor v2 vs quasar</title>
<style>
  :root {
    --fg: #111;
    --fg-muted: #555;
    --fg-faint: #888;
    --line: #eee;
    --line-strong: #ddd;
    --win: #080;
    --loss: #c00;
  }
  html { -webkit-text-size-adjust: 100%; }
  body {
    font: 13px/1.5 -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    color: var(--fg);
    background: #fff;
    max-width: 900px;
    margin: 40px auto;
    padding: 0 32px 80px;
  }
  h1 { font: 600 20px/1.2 -apple-system, "Segoe UI", sans-serif; margin: 0 0 4px; }
  h2 { font: 600 14px/1 -apple-system, "Segoe UI", sans-serif; margin: 40px 0 12px; }
  h3 {
    font: 500 12px/1 "SF Mono", Menlo, Consolas, monospace;
    color: var(--fg-muted);
    margin: 32px 0 10px;
    letter-spacing: 0.02em;
  }
  .meta { color: var(--fg-faint); font-size: 12px; margin-bottom: 32px; }
  table { width: 100%; border-collapse: collapse; font: 12px/1.5 "SF Mono", Menlo, Consolas, monospace; }
  th {
    text-align: right;
    font-weight: 500;
    color: var(--fg-muted);
    padding: 6px 0 6px 16px;
    border-bottom: 1px solid var(--line-strong);
  }
  th.l { text-align: left; padding-left: 0; }
  td {
    text-align: right;
    padding: 6px 0 6px 16px;
    border-bottom: 1px solid var(--line);
  }
  td.l { text-align: left; padding-left: 0; color: var(--fg); }
  td.win, th.win { color: var(--win); }
  td.loss, th.loss { color: var(--loss); }
  td.na { color: var(--fg-faint); }
  sup { font-size: 9px; }
  code { font: 11px "SF Mono", Menlo, Consolas, monospace; color: var(--fg-muted); }
  .note { font-size: 11px; color: var(--fg-faint); margin: 12px 0 0; line-height: 1.5; }
  .flame-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin: 8px 0 24px;
  }
  .flame { display: flex; flex-direction: column; min-width: 0; }
  .flame-label {
    font: 11px "SF Mono", Menlo, Consolas, monospace;
    color: var(--fg-faint);
    margin-bottom: 6px;
  }
  .flame a { display: block; border: 1px solid var(--line); }
  .flame img {
    display: block;
    width: 100%;
    height: auto;
  }
  .flame-miss {
    font: 11px "SF Mono", Menlo, Consolas, monospace;
    color: var(--fg-faint);
    padding: 40px 0;
    text-align: center;
    border: 1px dashed var(--line-strong);
  }
</style>
</head>
<body>
"#;
