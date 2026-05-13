use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::OpenOptions,
    net::{IpAddr, SocketAddr, TcpListener},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use chrono::Local;

use crate::{
    config::{self, Config},
    AppError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DoctorStatus {
    Pass,
    Warn,
    Fail,
    NotRun,
}

impl DoctorStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::NotRun => "NOT RUN",
        }
    }

    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Fail)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    status: DoctorStatus,
    message: String,
}

impl DoctorCheck {
    #[must_use]
    pub fn new(status: DoctorStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn status(&self) -> DoctorStatus {
        self.status
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorSection {
    name: String,
    checks: Vec<DoctorCheck>,
}

impl DoctorSection {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            checks: Vec::new(),
        }
    }

    pub fn push(&mut self, status: DoctorStatus, message: impl Into<String>) {
        self.checks.push(DoctorCheck::new(status, message));
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn checks(&self) -> &[DoctorCheck] {
        &self.checks
    }

    #[must_use]
    pub fn summary_status(&self) -> DoctorStatus {
        if self.checks.iter().any(|c| c.status == DoctorStatus::Fail) {
            DoctorStatus::Fail
        } else if self.checks.iter().any(|c| c.status == DoctorStatus::Warn) {
            DoctorStatus::Warn
        } else if self.checks.iter().all(|c| c.status == DoctorStatus::NotRun) {
            DoctorStatus::NotRun
        } else {
            DoctorStatus::Pass
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    data_dir: PathBuf,
    settings_path: Option<PathBuf>,
    doctor_log_path: Option<PathBuf>,
    doctor_log_required: bool,
    generated_at: Option<String>,
    sections: Vec<DoctorSection>,
}

impl DoctorReport {
    #[must_use]
    pub const fn new(data_dir: PathBuf, settings_path: Option<PathBuf>) -> Self {
        Self {
            data_dir,
            settings_path,
            doctor_log_path: None,
            doctor_log_required: false,
            generated_at: None,
            sections: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_doctor_log_path(mut self, path: PathBuf, required: bool) -> Self {
        self.doctor_log_path = Some(path);
        self.doctor_log_required = required;
        self
    }

    pub fn stamp_now(&mut self) {
        self.generated_at = Some(Local::now().to_rfc3339());
    }

    pub fn push_section(&mut self, section: DoctorSection) {
        self.sections.push(section);
    }

    #[must_use]
    pub fn sections(&self) -> &[DoctorSection] {
        &self.sections
    }

    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.sections
            .iter()
            .any(|section| section.summary_status().is_failure())
    }

    #[must_use]
    pub fn overall_status(&self) -> DoctorStatus {
        if self.has_failures() {
            DoctorStatus::Fail
        } else {
            DoctorStatus::Pass
        }
    }

    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::with_capacity(2_048);
        let _ = writeln!(out, "RustHost Doctor");
        let _ = writeln!(out);
        let _ = writeln!(out, "Data directory: {}", self.data_dir.display());
        if let Some(settings_path) = &self.settings_path {
            let _ = writeln!(out, "Settings: {}", settings_path.display());
        }
        if let Some(generated_at) = &self.generated_at {
            let _ = writeln!(out, "Generated: {generated_at}");
        }

        for section in &self.sections {
            let _ = writeln!(out);
            let _ = writeln!(out, "{}", section.name);
            for check in &section.checks {
                let _ = writeln!(out, "{} {}", check.status.label(), check.message);
            }
        }

        let _ = writeln!(out);
        let _ = writeln!(out, "Result");
        if self.has_failures() {
            let _ = writeln!(out, "FAIL RustHost is not ready to start.");
        } else {
            let _ = writeln!(out, "PASS RustHost appears ready to start.");
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorContext {
    CommandLine,
    TuiLive(DoctorLiveState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoctorLiveState {
    pub server_running: bool,
    pub actual_port: u16,
    pub tls_running: bool,
    pub tls_port: Option<u16>,
}

#[must_use]
pub fn run_fast_doctor(
    data_dir: &Path,
    settings_path: &Path,
    context: DoctorContext,
) -> DoctorReport {
    let mut report = DoctorReport::new(data_dir.to_path_buf(), Some(settings_path.to_path_buf()));
    report.stamp_now();

    let (config, config_section) = check_config(settings_path);
    report.push_section(config_section);

    if let Some(config) = config {
        report =
            report.with_doctor_log_path(doctor_log_path(data_dir, &config), config.logging.enabled);
        report.push_section(check_paths(data_dir, &config));
        report.push_section(check_network(&config, context));
        report.push_section(check_tls(data_dir, &config, context));
        report.push_section(check_tor(data_dir, &config, context));
        report.push_section(check_favicon(data_dir, &config));
        report.push_section(check_logs(data_dir, &config));
    } else {
        report.push_section(not_run_section(
            "Paths",
            "settings.toml must load before path checks run",
        ));
        report.push_section(not_run_section(
            "Network",
            "settings.toml must load before bind checks run",
        ));
        report.push_section(not_run_section(
            "TLS",
            "settings.toml must load before TLS checks run",
        ));
        report.push_section(not_run_section(
            "Tor",
            "settings.toml must load before Tor checks run",
        ));
        report.push_section(not_run_section(
            "Favicon",
            "settings.toml must load before favicon checks run",
        ));
        report.push_section(not_run_section(
            "Logs",
            "settings.toml must load before log checks run",
        ));
    }

    report
}

#[must_use]
pub fn run_fast_doctor_for_loaded_config(
    data_dir: &Path,
    settings_path: Option<&Path>,
    config: &Config,
    context: DoctorContext,
) -> DoctorReport {
    let mut report =
        DoctorReport::new(data_dir.to_path_buf(), settings_path.map(Path::to_path_buf))
            .with_doctor_log_path(doctor_log_path(data_dir, config), config.logging.enabled);
    report.stamp_now();
    let mut config_section = DoctorSection::new("Config");
    if let Some(settings_path) = settings_path {
        config_section.push(
            DoctorStatus::Pass,
            format!("settings.toml loaded from {}", settings_path.display()),
        );
    } else {
        config_section.push(
            DoctorStatus::Pass,
            "in-memory one-shot configuration is active",
        );
    }
    config_section.push(DoctorStatus::Pass, "required values were valid at startup");
    report.push_section(config_section);
    report.push_section(check_paths(data_dir, config));
    report.push_section(check_network(config, context));
    report.push_section(check_tls(data_dir, config, context));
    report.push_section(check_tor(data_dir, config, context));
    report.push_section(check_favicon(data_dir, config));
    report.push_section(check_logs(data_dir, config));
    report
}

#[must_use]
pub fn run_deep_checks(config: &Config, data_dir: &Path, live: DoctorLiveState) -> DoctorSection {
    let mut section = DoctorSection::new("Deep Checks");

    if live.server_running && live.actual_port != 0 {
        let addr = loopback_addr(config.server.bind, live.actual_port);
        match connect_with_timeout(addr, Duration::from_millis(750)) {
            Ok(()) => section.push(
                DoctorStatus::Pass,
                format!("local HTTP listener accepted a connection on {addr}"),
            ),
            Err(err) => section.push(
                DoctorStatus::Warn,
                format!("local HTTP listener was not confirmed on {addr}: {err}"),
            ),
        }
    } else {
        section.push(
            DoctorStatus::NotRun,
            "local request check skipped because HTTP listener is not running",
        );
    }

    if config.tls.enabled {
        if live.tls_running {
            if let Some(port) = live.tls_port {
                let addr = loopback_addr(config.server.bind, port);
                match connect_with_timeout(addr, Duration::from_millis(750)) {
                    Ok(()) => section.push(
                        DoctorStatus::Pass,
                        format!("local TLS listener accepted a TCP connection on {addr}"),
                    ),
                    Err(err) => section.push(
                        DoctorStatus::Warn,
                        format!("local TLS listener was not confirmed on {addr}: {err}"),
                    ),
                }
            }
        } else {
            section.push(
                DoctorStatus::Warn,
                "TLS handshake not attempted because the HTTPS listener is not running",
            );
        }
    } else {
        section.push(
            DoctorStatus::NotRun,
            "TLS is disabled in settings; certificate/key checks were skipped.",
        );
    }

    if config.tor.enabled {
        let state = data_dir.join("runtime/tor/arti_state");
        let cache = data_dir.join("runtime/tor/arti_cache");
        if state.is_dir() && cache.is_dir() {
            section.push(DoctorStatus::Pass, "Tor state/cache directories exist");
        } else {
            section.push(
                DoctorStatus::NotRun,
                "Tor bootstrap state was not checked because Doctor does not wait for bootstrap.",
            );
        }
    } else {
        section.push(DoctorStatus::NotRun, "Tor support is disabled in settings.");
    }

    section.push(
        DoctorStatus::NotRun,
        "Doctor avoids external public reachability checks by default to prevent flaky network-dependent results. Use a separate browser/curl test against your public URL if needed.",
    );
    section.push(
        DoctorStatus::NotRun,
        "Doctor does not perform load testing; use the static stress test or external tooling for capacity testing.",
    );
    section
}

pub fn append_deep_checks(report: &mut DoctorReport, section: DoctorSection) {
    if let Some(existing) = report
        .sections
        .iter_mut()
        .find(|candidate| candidate.name == "Deep Checks")
    {
        *existing = section;
    } else {
        report.push_section(section);
    }
}

#[must_use]
pub fn deep_checks_not_run_section() -> DoctorSection {
    let mut section = DoctorSection::new("Deep Checks");
    section.push(
        DoctorStatus::NotRun,
        "press D to run bounded interactive checks",
    );
    section
}

pub fn write_doctor_log(report: &mut DoctorReport) {
    let Some(log_path) = report.doctor_log_path.clone() else {
        return;
    };
    set_log_write_status(
        report,
        DoctorStatus::Pass,
        format!(
            "doctor.log is intentionally written at {}",
            log_path.display()
        ),
    );
    let text = report.render_text();
    match write_log_file(&log_path, &text) {
        Ok(()) => {}
        Err(err) => {
            let status = if report.doctor_log_required {
                DoctorStatus::Fail
            } else {
                DoctorStatus::Warn
            };
            set_log_write_status(
                report,
                status,
                format!("doctor.log could not be written: {err}"),
            );
        }
    }
}

fn check_config(settings_path: &Path) -> (Option<Config>, DoctorSection) {
    let mut section = DoctorSection::new("Config");
    if !settings_path.exists() {
        section.push(
            DoctorStatus::Fail,
            format!("settings.toml not found at {}", settings_path.display()),
        );
        return (None, section);
    }
    section.push(DoctorStatus::Pass, "settings.toml found");

    match config::loader::load(settings_path) {
        Ok(config) => {
            section.push(DoctorStatus::Pass, "settings.toml parsed successfully");
            section.push(DoctorStatus::Pass, "required values are valid");
            (Some(config), section)
        }
        Err(AppError::ConfigValidation(errors)) => {
            section.push(
                DoctorStatus::Fail,
                format!(
                    "settings.toml parsed with {} validation error(s)",
                    errors.len()
                ),
            );
            for error in errors {
                section.push(DoctorStatus::Fail, error);
            }
            (None, section)
        }
        Err(AppError::ConfigLoad(message)) => {
            section.push(DoctorStatus::Fail, message);
            (None, section)
        }
        Err(err) => {
            section.push(DoctorStatus::Fail, err.to_string());
            (None, section)
        }
    }
}

fn check_paths(data_dir: &Path, config: &Config) -> DoctorSection {
    let mut section = DoctorSection::new("Paths");
    check_directory_usable(&mut section, "data directory", data_dir, true);
    check_directory_usable(
        &mut section,
        "runtime directory",
        &runtime_dir(data_dir),
        true,
    );

    let site_root = data_dir.join(&config.site.directory);
    match std::fs::metadata(&site_root) {
        Ok(meta) if meta.is_dir() => section.push(DoctorStatus::Pass, "site directory exists"),
        Ok(_) => section.push(
            DoctorStatus::Fail,
            format!("site directory is not a directory: {}", site_root.display()),
        ),
        Err(err) => section.push(
            DoctorStatus::Fail,
            format!(
                "site directory is not usable at {}: {err}",
                site_root.display()
            ),
        ),
    }
    check_contained(&mut section, "site root", data_dir, &site_root);

    let logs_dir = logs_dir(data_dir, config);
    check_directory_usable(
        &mut section,
        "logs directory",
        &logs_dir,
        config.logging.enabled,
    );
    section
}

fn check_network(config: &Config, context: DoctorContext) -> DoctorSection {
    let mut section = DoctorSection::new("Network");
    let requested = requested_binds(config);
    let mut by_addr: BTreeMap<SocketAddr, Vec<&'static str>> = BTreeMap::new();
    for (label, addr) in requested {
        by_addr.entry(addr).or_default().push(label);
    }

    for (addr, labels) in by_addr {
        if labels.len() > 1 {
            section.push(
                DoctorStatus::Fail,
                format!(
                    "duplicate bind target {addr} is configured for {}",
                    labels.join(", ")
                ),
            );
            continue;
        }

        let label = labels.first().copied().unwrap_or("listener");
        match context {
            DoctorContext::TuiLive(live) if live_owns_bind(label, addr, live) => section.push(
                DoctorStatus::Pass,
                format!("{label} bind {addr} is active in this RustHost process"),
            ),
            _ => match TcpListener::bind(addr) {
                Ok(listener) => {
                    drop(listener);
                    section.push(
                        DoctorStatus::Pass,
                        format!("{label} bind {addr} is available"),
                    );
                }
                Err(err) => section.push(
                    DoctorStatus::Fail,
                    format!("{label} bind {addr} failed: {err}"),
                ),
            },
        }
    }

    if config.tls.redirect_http {
        section.push(DoctorStatus::Pass, "HTTP->HTTPS redirect is enabled");
    } else {
        section.push(
            DoctorStatus::NotRun,
            "HTTP redirect is disabled in settings.",
        );
    }
    let message = match context {
        DoctorContext::CommandLine => {
            "Doctor avoids external public reachability checks by default to prevent flaky network-dependent results. Use a separate browser/curl test against your public URL if needed."
        }
        DoctorContext::TuiLive(_) => {
            "Public reachability is not probed by the fast Doctor pass; use Deep Checks or a separate browser/curl test against your public URL if needed."
        }
    };
    section.push(DoctorStatus::NotRun, message);
    section
}

fn check_tls(data_dir: &Path, config: &Config, context: DoctorContext) -> DoctorSection {
    let mut section = DoctorSection::new("TLS");
    if !config.tls.enabled {
        section.push(
            DoctorStatus::NotRun,
            "TLS is disabled in settings; certificate/key checks were skipped.",
        );
        return section;
    }

    section.push(DoctorStatus::Pass, "TLS enabled");
    if config.tls.acme.enabled {
        check_acme_config(&mut section, data_dir, config);
    } else if let Some(manual) = &config.tls.manual_cert {
        check_relative_file(
            &mut section,
            data_dir,
            &manual.cert_path,
            "certificate file",
        );
        check_relative_file(&mut section, data_dir, &manual.key_path, "private key file");
    } else {
        let dev_dir = data_dir.join("runtime/tls/dev");
        check_directory_usable(&mut section, "self-signed TLS directory", &dev_dir, true);
        section.push(
            DoctorStatus::Warn,
            "no manual_cert or ACME config set; startup will use a self-signed development certificate",
        );
    }
    match context {
        DoctorContext::CommandLine => section.push(
            DoctorStatus::NotRun,
            "Browser TLS handshakes are not run by command-line Doctor.",
        ),
        DoctorContext::TuiLive(_) => section.push(
            DoctorStatus::NotRun,
            "TLS listener probing is reported by Deep Checks; the fast Doctor pass does not open a TLS client connection.",
        ),
    }
    section
}

fn check_tor(data_dir: &Path, config: &Config, context: DoctorContext) -> DoctorSection {
    let mut section = DoctorSection::new("Tor");
    if !config.tor.enabled {
        section.push(DoctorStatus::NotRun, "Tor support is disabled in settings.");
        return section;
    }

    section.push(DoctorStatus::Pass, "Tor enabled");
    for label in ["runtime/tor/arti_state", "runtime/tor/arti_cache"] {
        let path = data_dir.join(label);
        check_directory_usable(&mut section, label, &path, true);
        check_no_symlink_chain(&mut section, label, &path);
    }
    match context {
        DoctorContext::CommandLine => section.push(
            DoctorStatus::NotRun,
            "Tor bootstrap is not checked by the fast command-line Doctor pass.",
        ),
        DoctorContext::TuiLive(_) => section.push(
            DoctorStatus::NotRun,
            "Tor bootstrap is reported by Deep Checks and the runtime dashboard; the fast Doctor pass does not wait for bootstrap.",
        ),
    }
    section
}

fn check_favicon(data_dir: &Path, config: &Config) -> DoctorSection {
    let mut section = DoctorSection::new("Favicon");
    let site_root = data_dir.join(&config.site.directory);
    let favicon = site_root.join(&config.site.favicon);
    check_contained(&mut section, "favicon path", &site_root, &favicon);
    match std::fs::File::open(&favicon) {
        Ok(_) => section.push(
            DoctorStatus::Pass,
            "/favicon.ico source exists and is readable",
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => section.push(
            DoctorStatus::Warn,
            format!("favicon source does not exist at {}", favicon.display()),
        ),
        Err(err) => section.push(
            DoctorStatus::Fail,
            format!(
                "favicon source is not readable at {}: {err}",
                favicon.display()
            ),
        ),
    }
    section
}

fn check_logs(data_dir: &Path, config: &Config) -> DoctorSection {
    let mut section = DoctorSection::new("Logs");
    let dir = logs_dir(data_dir, config);
    check_directory_usable(&mut section, "logs directory", &dir, config.logging.enabled);
    section.push(
        DoctorStatus::NotRun,
        "doctor.log is the only intentional Doctor write and is recorded after report rendering",
    );
    section
}

fn not_run_section(name: &str, message: &str) -> DoctorSection {
    let mut section = DoctorSection::new(name);
    section.push(DoctorStatus::NotRun, message);
    section
}

fn runtime_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("runtime")
}

fn logs_dir(data_dir: &Path, config: &Config) -> PathBuf {
    data_dir
        .join(&config.logging.file)
        .parent()
        .map_or_else(|| data_dir.to_path_buf(), Path::to_path_buf)
}

fn doctor_log_path(data_dir: &Path, config: &Config) -> PathBuf {
    logs_dir(data_dir, config).join("doctor.log")
}

fn check_directory_usable(section: &mut DoctorSection, label: &str, path: &Path, required: bool) {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            section.push(DoctorStatus::Pass, format!("{label} exists"));
            if metadata.permissions().readonly() {
                let status = if required {
                    DoctorStatus::Fail
                } else {
                    DoctorStatus::Warn
                };
                section.push(
                    status,
                    format!("{label} is marked read-only at {}", path.display()),
                );
            } else {
                section.push(
                    DoctorStatus::Pass,
                    format!("{label} is not marked read-only"),
                );
            }
        }
        Ok(_) => section.push(
            DoctorStatus::Fail,
            format!("{label} path is not a directory: {}", path.display()),
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let status = if required {
                DoctorStatus::Fail
            } else {
                DoctorStatus::Warn
            };
            section.push(
                status,
                format!(
                    "{label} does not exist at {}; Doctor will not create it",
                    path.display()
                ),
            );
        }
        Err(err) => {
            let status = if required {
                DoctorStatus::Fail
            } else {
                DoctorStatus::Warn
            };
            section.push(
                status,
                format!("{label} cannot be inspected at {}: {err}", path.display()),
            );
        }
    }
}

fn check_contained(section: &mut DoctorSection, label: &str, base: &Path, candidate: &Path) {
    match (base.canonicalize(), candidate.canonicalize()) {
        (Ok(base), Ok(candidate)) if candidate.starts_with(&base) => {
            section.push(DoctorStatus::Pass, format!("{label} is contained safely"));
        }
        (Ok(_), Ok(candidate)) => section.push(
            DoctorStatus::Fail,
            format!("{label} escapes required root: {}", candidate.display()),
        ),
        (_, Err(err)) if err.kind() == std::io::ErrorKind::NotFound => section.push(
            DoctorStatus::Warn,
            format!("{label} target does not exist yet: {}", candidate.display()),
        ),
        (_, Err(err)) => section.push(
            DoctorStatus::Fail,
            format!(
                "{label} cannot be resolved at {}: {err}",
                candidate.display()
            ),
        ),
        (Err(err), _) => section.push(
            DoctorStatus::Fail,
            format!(
                "{label} root cannot be resolved at {}: {err}",
                base.display()
            ),
        ),
    }
}

fn check_no_symlink_chain(section: &mut DoctorSection, label: &str, path: &Path) {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.as_os_str().is_empty() {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                section.push(
                    DoctorStatus::Fail,
                    format!(
                        "{label} path contains symlink component {}",
                        current.display()
                    ),
                );
                return;
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                section.push(
                    DoctorStatus::Fail,
                    format!(
                        "{label} path cannot be inspected at {}: {err}",
                        current.display()
                    ),
                );
                return;
            }
        }
    }
    section.push(
        DoctorStatus::Pass,
        format!("{label} path contains no symlink components"),
    );
}

fn check_acme_config(section: &mut DoctorSection, data_dir: &Path, config: &Config) {
    if config.tls.acme.domains.is_empty() {
        section.push(
            DoctorStatus::Fail,
            "[tls.acme] requires at least one domain in domains",
        );
    } else {
        section.push(DoctorStatus::Pass, "ACME domain list is configured");
    }
    if contains_unsafe_component(Path::new(&config.tls.acme.cache_dir)) {
        section.push(
            DoctorStatus::Fail,
            "[tls.acme.cache_dir] must be relative and must not contain '..'",
        );
    } else {
        let cache = data_dir.join(&config.tls.acme.cache_dir);
        check_directory_usable(section, "ACME cache directory", &cache, true);
    }
    section.push(
        DoctorStatus::NotRun,
        "ACME issuance and public certificate validation are not run by Doctor.",
    );
}

fn check_relative_file(section: &mut DoctorSection, data_dir: &Path, value: &str, label: &str) {
    let rel = Path::new(value);
    if contains_unsafe_component(rel) {
        section.push(
            DoctorStatus::Fail,
            format!("{label} path must be relative and must not contain '..'"),
        );
        return;
    }
    let path = data_dir.join(rel);
    check_contained(section, label, data_dir, &path);
    match std::fs::File::open(&path) {
        Ok(_) => section.push(
            DoctorStatus::Pass,
            format!("{label} exists and is readable"),
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => section.push(
            DoctorStatus::Fail,
            format!("{label} does not exist at {}", path.display()),
        ),
        Err(err) => section.push(
            DoctorStatus::Fail,
            format!("{label} is not readable at {}: {err}", path.display()),
        ),
    }
}

fn contains_unsafe_component(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    })
}

fn requested_binds(config: &Config) -> Vec<(&'static str, SocketAddr)> {
    let mut binds = Vec::with_capacity(3);
    if !(config.tls.enabled && config.tls.redirect_http) {
        binds.push((
            "HTTP",
            SocketAddr::new(config.server.bind, config.server.port.get()),
        ));
    }
    if config.tls.enabled {
        binds.push((
            "HTTPS",
            SocketAddr::new(config.server.bind, config.tls.port.get()),
        ));
        if config.tls.redirect_http {
            binds.push((
                "HTTP redirect",
                SocketAddr::new(config.server.bind, config.tls.http_port.get()),
            ));
        }
    }
    binds
}

fn live_owns_bind(label: &str, addr: SocketAddr, live: DoctorLiveState) -> bool {
    match label {
        "HTTP" | "HTTP redirect" => live.server_running && live.actual_port == addr.port(),
        "HTTPS" => live.tls_running && live.tls_port == Some(addr.port()),
        _ => false,
    }
}

const fn loopback_addr(bind: IpAddr, port: u16) -> SocketAddr {
    match bind {
        IpAddr::V4(addr) if addr.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port)
        }
        IpAddr::V6(addr) if addr.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), port)
        }
        addr => SocketAddr::new(addr, port),
    }
}

fn connect_with_timeout(addr: SocketAddr, timeout: Duration) -> std::io::Result<()> {
    std::net::TcpStream::connect_timeout(&addr, timeout).map(|_| ())
}

fn write_log_file(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?
        .write_all_text(text)
}

trait WriteAllText {
    fn write_all_text(self, text: &str) -> std::io::Result<()>;
}

impl WriteAllText for std::fs::File {
    fn write_all_text(mut self, text: &str) -> std::io::Result<()> {
        use std::io::Write as _;
        self.write_all(text.as_bytes())?;
        self.flush()
    }
}

fn set_log_write_status(
    report: &mut DoctorReport,
    status: DoctorStatus,
    message: impl Into<String>,
) {
    let message = message.into();
    if let Some(section) = report
        .sections
        .iter_mut()
        .find(|candidate| candidate.name == "Logs")
    {
        if let Some(check) = section
            .checks
            .iter_mut()
            .find(|check| check.message.contains("doctor.log"))
        {
            *check = DoctorCheck::new(status, message);
            return;
        }
        section.push(status, message);
    }
}

#[must_use]
pub const fn status_style_label(status: DoctorStatus) -> (&'static str, &'static str) {
    match status {
        DoctorStatus::Pass => ("PASS", "\x1b[32m"),
        DoctorStatus::Warn => ("WARN", "\x1b[33m"),
        DoctorStatus::Fail => ("FAIL", "\x1b[31m"),
        DoctorStatus::NotRun => ("NOT RUN", "\x1b[2m"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::num::NonZeroU16;

    fn write_settings(dir: &Path, body: &str) {
        std::fs::create_dir_all(dir.join("site")).expect("site dir");
        std::fs::write(dir.join("site/index.html"), b"ok").expect("index");
        std::fs::write(dir.join("site/favicon.ico"), b"ico").expect("favicon");
        std::fs::write(dir.join("settings.toml"), body).expect("settings");
    }

    fn default_settings(port: u16) -> String {
        format!(
            r#"
[server]
port = {port}
bind = "127.0.0.1"

[site]
directory = "site"
index_file = "index.html"
favicon = "favicon.ico"

[tor]
enabled = false

[logging]
enabled = true
file = "runtime/logs/rusthost.log"

[console]
interactive = false
refresh_rate_ms = 500

[identity]
instance_name = "RustHost"

[tls]
enabled = false
"#
        )
    }

    fn has_line(report: &DoctorReport, status: DoctorStatus, needle: &str) -> bool {
        report.sections.iter().any(|section| {
            section
                .checks
                .iter()
                .any(|check| check.status == status && check.message.contains(needle))
        })
    }

    #[test]
    fn missing_settings_is_clear_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let report = run_fast_doctor(
            tmp.path(),
            &tmp.path().join("settings.toml"),
            DoctorContext::CommandLine,
        );
        assert!(report.has_failures());
        assert!(has_line(
            &report,
            DoctorStatus::Fail,
            "settings.toml not found"
        ));
    }

    #[test]
    fn invalid_config_validation_fails() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let settings =
            default_settings(19082).replace("port = 19082", "port = 19082\nmax_connections = 0");
        write_settings(tmp.path(), &settings);
        let report = run_fast_doctor(
            tmp.path(),
            &tmp.path().join("settings.toml"),
            DoctorContext::CommandLine,
        );
        assert!(report.has_failures());
        assert!(has_line(&report, DoctorStatus::Fail, "max_connections"));
    }

    #[test]
    fn address_in_use_is_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) => {
                assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
                return;
            }
        };
        let port = listener.local_addr().expect("addr").port();
        write_settings(tmp.path(), &default_settings(port));
        let report = run_fast_doctor(
            tmp.path(),
            &tmp.path().join("settings.toml"),
            DoctorContext::CommandLine,
        );
        assert!(report.has_failures());
        assert!(has_line(&report, DoctorStatus::Fail, "failed"));
    }

    #[test]
    fn tls_enabled_missing_manual_cert_fails() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let settings = default_settings(19080).replace(
            "[tls]\nenabled = false",
            r#"[tls]
enabled = true
manual_cert = { cert_path = "missing.crt", key_path = "missing.key" }"#,
        );
        write_settings(tmp.path(), &settings);
        let report = run_fast_doctor(
            tmp.path(),
            &tmp.path().join("settings.toml"),
            DoctorContext::CommandLine,
        );
        assert!(report.has_failures());
        assert!(has_line(
            &report,
            DoctorStatus::Fail,
            "certificate file does not exist"
        ));
    }

    #[test]
    fn tls_disabled_does_not_require_cert_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_settings(tmp.path(), &default_settings(19081));
        let report = run_fast_doctor(
            tmp.path(),
            &tmp.path().join("settings.toml"),
            DoctorContext::CommandLine,
        );
        assert!(!has_line(&report, DoctorStatus::Fail, "certificate"));
        assert!(!has_line(&report, DoctorStatus::Warn, "TLS disabled"));
        assert!(has_line(
            &report,
            DoctorStatus::NotRun,
            "TLS is disabled in settings"
        ));
    }

    #[test]
    fn disabled_features_are_not_warnings() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_settings(tmp.path(), &default_settings(19083));
        let report = run_fast_doctor(
            tmp.path(),
            &tmp.path().join("settings.toml"),
            DoctorContext::CommandLine,
        );

        assert!(has_line(
            &report,
            DoctorStatus::NotRun,
            "HTTP redirect is disabled"
        ));
        assert!(has_line(
            &report,
            DoctorStatus::NotRun,
            "Tor support is disabled"
        ));
        assert!(!has_line(
            &report,
            DoctorStatus::Warn,
            "HTTP->HTTPS redirect is disabled"
        ));
        assert!(!has_line(&report, DoctorStatus::Warn, "Tor disabled"));
    }

    #[test]
    fn skipped_external_checks_are_not_warnings() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_settings(tmp.path(), &default_settings(19084));
        let report = run_fast_doctor(
            tmp.path(),
            &tmp.path().join("settings.toml"),
            DoctorContext::CommandLine,
        );

        assert!(has_line(
            &report,
            DoctorStatus::NotRun,
            "Doctor avoids external public reachability checks"
        ));
        assert!(!has_line(
            &report,
            DoctorStatus::Warn,
            "reachability not tested"
        ));
    }

    #[test]
    fn warn_only_report_exits_success_equivalent() {
        let mut report =
            DoctorReport::new(PathBuf::from("data"), Some(PathBuf::from("settings.toml")));
        let mut section = DoctorSection::new("Only Warns");
        section.push(DoctorStatus::Warn, "warning");
        report.push_section(section);
        assert!(!report.has_failures());
        assert_eq!(report.overall_status(), DoctorStatus::Pass);
    }

    #[test]
    fn fail_report_exits_failure_equivalent() {
        let mut report =
            DoctorReport::new(PathBuf::from("data"), Some(PathBuf::from("settings.toml")));
        let mut section = DoctorSection::new("Failure");
        section.push(DoctorStatus::Fail, "failure");
        report.push_section(section);
        assert!(report.has_failures());
        assert_eq!(report.overall_status(), DoctorStatus::Fail);
    }

    #[test]
    fn text_render_contains_sections_and_result() {
        let mut report =
            DoctorReport::new(PathBuf::from("data"), Some(PathBuf::from("settings.toml")));
        let mut section = DoctorSection::new("Config");
        section.push(DoctorStatus::Pass, "settings.toml found");
        report.push_section(section);
        let text = report.render_text();
        assert!(text.contains("RustHost Doctor"));
        assert!(text.contains("Config"));
        assert!(text.contains("PASS settings.toml found"));
        assert!(text.contains("Result"));
    }

    #[test]
    fn status_style_labels_are_mapped() {
        assert_eq!(status_style_label(DoctorStatus::Pass).0, "PASS");
        assert_eq!(status_style_label(DoctorStatus::Warn).0, "WARN");
        assert_eq!(status_style_label(DoctorStatus::Fail).0, "FAIL");
        assert_eq!(status_style_label(DoctorStatus::NotRun).0, "NOT RUN");
    }

    #[test]
    fn duplicate_bind_targets_are_not_bound_twice() {
        let mut config = Config::default();
        config.tor.enabled = false;
        config.tls.enabled = true;
        config.tls.redirect_http = false;
        config.server.port = NonZeroU16::new(19443).expect("port");
        config.tls.port = NonZeroU16::new(19443).expect("port");
        let section = check_network(&config, DoctorContext::CommandLine);
        assert!(section
            .checks()
            .iter()
            .any(|check| check.status() == DoctorStatus::Fail
                && check.message().contains("duplicate bind target")));
    }

    #[test]
    fn deep_checks_are_separate_from_fast_readiness() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut report = DoctorReport::new(tmp.path().to_path_buf(), None);
        let deep = run_deep_checks(
            &Config::default(),
            tmp.path(),
            DoctorLiveState {
                server_running: false,
                actual_port: 0,
                tls_running: false,
                tls_port: None,
            },
        );
        append_deep_checks(&mut report, deep);
        assert!(report
            .sections()
            .iter()
            .any(|section| section.name() == "Deep Checks"));
    }

    #[test]
    fn loaded_config_doctor_does_not_reload_settings_from_disk() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("site")).expect("site");
        std::fs::create_dir_all(tmp.path().join("runtime")).expect("runtime");
        std::fs::write(tmp.path().join("site/index.html"), b"ok").expect("index");
        std::fs::write(tmp.path().join("settings.toml"), "not valid toml").expect("settings");

        let mut config = Config::default();
        config.tor.enabled = false;
        config.logging.enabled = false;
        config.server.port = NonZeroU16::new(19185).expect("port");

        let report = run_fast_doctor_for_loaded_config(
            tmp.path(),
            Some(&tmp.path().join("settings.toml")),
            &config,
            DoctorContext::TuiLive(DoctorLiveState {
                server_running: false,
                actual_port: 0,
                tls_running: false,
                tls_port: None,
            }),
        );

        assert!(has_line(
            &report,
            DoctorStatus::Pass,
            "settings.toml loaded from"
        ));
        assert!(!has_line(&report, DoctorStatus::Fail, "not valid toml"));
        assert!(!has_line(
            &report,
            DoctorStatus::Fail,
            "settings.toml parsed"
        ));
    }

    #[test]
    fn doctor_checks_do_not_create_missing_runtime_log_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("site")).expect("site");
        std::fs::create_dir_all(tmp.path().join("runtime")).expect("runtime");
        std::fs::write(tmp.path().join("site/index.html"), b"ok").expect("index");

        let mut config = Config::default();
        config.tor.enabled = false;
        config.logging.enabled = true;
        config.logging.file = "runtime/logs/rusthost.log".into();
        config.server.port = NonZeroU16::new(19186).expect("port");

        let _report = run_fast_doctor_for_loaded_config(
            tmp.path(),
            None,
            &config,
            DoctorContext::CommandLine,
        );

        assert!(!tmp.path().join("runtime/logs").exists());
        assert!(!tmp
            .path()
            .join("runtime/logs/.rusthost-doctor-write-test")
            .exists());
    }

    #[test]
    fn doctor_directory_checks_do_not_probe_write_existing_directories() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("site")).expect("site");
        std::fs::create_dir_all(tmp.path().join("runtime/logs")).expect("logs");
        std::fs::write(tmp.path().join("site/index.html"), b"ok").expect("index");

        let mut config = Config::default();
        config.tor.enabled = false;
        config.logging.enabled = true;
        config.logging.file = "runtime/logs/rusthost.log".into();
        config.server.port = NonZeroU16::new(19188).expect("port");

        let report = run_fast_doctor_for_loaded_config(
            tmp.path(),
            None,
            &config,
            DoctorContext::CommandLine,
        );

        assert!(!tmp
            .path()
            .join("runtime/logs/.rusthost-doctor-write-test")
            .exists());
        assert!(has_line(
            &report,
            DoctorStatus::Pass,
            "logs directory is not marked read-only"
        ));
    }

    #[test]
    fn doctor_log_write_is_intentional_side_effect() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("site")).expect("site");
        std::fs::create_dir_all(tmp.path().join("runtime")).expect("runtime");
        std::fs::write(tmp.path().join("site/index.html"), b"ok").expect("index");

        let mut config = Config::default();
        config.tor.enabled = false;
        config.logging.enabled = true;
        config.logging.file = "runtime/logs/rusthost.log".into();
        config.server.port = NonZeroU16::new(19187).expect("port");

        let mut report = run_fast_doctor_for_loaded_config(
            tmp.path(),
            None,
            &config,
            DoctorContext::CommandLine,
        );
        write_doctor_log(&mut report);

        assert!(tmp.path().join("runtime/logs/doctor.log").is_file());
        assert!(has_line(
            &report,
            DoctorStatus::Pass,
            "doctor.log is intentionally written"
        ));
    }
}
