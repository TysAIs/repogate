// RepoGate Rust spike: tree walk + regex rule subset, for size/speed evidence.
use regex::Regex;
use std::time::Instant;
use walkdir::WalkDir;

fn main() {
    let root = std::env::args().nth(1).expect("usage: repogate-spike <dir>");
    let patterns: Vec<(&str, Regex)> = [
        ("net-curl-pipe-shell", r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba)?sh\b"),
        ("net-metadata-ip", r"169\.254\.169\.254"),
        ("net-webhook", r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot"),
        ("cred-ssh-aws", r"\.ssh[/\\]|\.aws[/\\]credentials|id_rsa|id_ed25519"),
        ("cred-browser", r"Login Data|Cookies\.sqlite|Chrome[/\\]User Data"),
        ("exec-eval", r"\beval\s*\(|\bexec\s*\(|os\.system\s*\("),
        ("exec-indirection", r#"getattr\s*\([^,]+,\s*['"][^'"]*(system|popen|exec)"#),
        ("obf-long-blob", r"[A-Za-z0-9+/=]{400,}"),
        ("pi-ignore", r"ignore (all )?(previous|prior|above) instructions"),
        ("pi-exfil", r"do not (tell|inform|mention to) the user"),
        ("net-raw-ip", r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        ("persist-os", r"crontab\s+-|systemctl\s+enable|schtasks\s+/create"),
        ("gate-env-ci", r"process\.env\.(CI|GITHUB_ACTIONS|GITLAB_CI)\b"),
        ("hook-folderopen", r#""runOn"\s*:\s*"folderOpen""#),
        ("exec-agent-lotl", r"--dangerously-skip-permissions|--yolo"),
        ("net-download-exec", r"DownloadString\(|DownloadFile\("),
    ]
    .iter()
    .map(|(id, p)| (*id, Regex::new(p).unwrap()))
    .collect();

    let t0 = Instant::now();
    let mut files = 0usize;
    let mut hits: Vec<usize> = vec![0; patterns.len()];
    for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.components().any(|c| c.as_os_str() == ".git") {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() > 8 * 1024 * 1024 {
            continue;
        }
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if data.contains(&0) {
            continue;
        }
        let text = String::from_utf8_lossy(&data);
        files += 1;
        for (i, (_, re)) in patterns.iter().enumerate() {
            if re.is_match(&text) {
                hits[i] += 1;
            }
        }
    }
    let total: usize = hits.iter().sum();
    println!("files scanned: {files}");
    println!("files with >=1 hit: n/a; total rule-file hits: {total}");
    for (i, (id, _)) in patterns.iter().enumerate() {
        if hits[i] > 0 {
            println!("  {id}: {}", hits[i]);
        }
    }
    println!("elapsed: {:.3}s", t0.elapsed().as_secs_f64());
}
