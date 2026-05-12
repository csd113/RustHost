#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Home,
    Logs,
    Doctor,
    Diagnostics,
    Tor,
    Network,
    Site,
    Settings,
    Help,
}

impl Page {
    pub const ALL: [Self; 9] = [
        Self::Home,
        Self::Logs,
        Self::Doctor,
        Self::Diagnostics,
        Self::Tor,
        Self::Network,
        Self::Site,
        Self::Settings,
        Self::Help,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Logs => "Logs",
            Self::Doctor => "Doctor",
            Self::Diagnostics => "Diagnostics",
            Self::Tor => "Tor",
            Self::Network => "Network",
            Self::Site => "Site",
            Self::Settings => "Settings",
            Self::Help => "Help",
        }
    }

    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Home => "Return to the main RustHost dashboard.",
            Self::Logs => "Inspect recent RustHost log output.",
            Self::Doctor => "Check config, paths, ports, TLS, Tor, favicon, and runtime safety.",
            Self::Diagnostics => "Collect operator diagnostics for troubleshooting.",
            Self::Tor => {
                "Inspect Tor onion service status, connectivity, controls, and detailed status."
            }
            Self::Network => "Inspect bind addresses, ports, HTTPS, and network reachability.",
            Self::Site => "Inspect the configured site directory and served content.",
            Self::Settings => "Review runtime settings and configuration choices.",
            Self::Help => "Find RustHost console help and command guidance.",
        }
    }

    #[must_use]
    pub const fn placeholder_text(self) -> &'static str {
        match self {
            Self::Home => "The dashboard already provides the current home view.",
            Self::Logs => "The dedicated logs page will be expanded later.",
            Self::Doctor => "Doctor checks will be added here as the console tools grow.",
            Self::Tor => "Tor controls and detailed status will be added here later.",
            Self::Network => "Network diagnostics and listener details will be added here later.",
            Self::Site => {
                "Site inspection and content management details will be added here later."
            }
            Self::Settings => "Settings inspection and editing controls will be added here later.",
            Self::Diagnostics => {
                "Diagnostics collection and export tools will be added here later."
            }
            Self::Help => "Expanded in-menu help content will be added here later.",
        }
    }
}
