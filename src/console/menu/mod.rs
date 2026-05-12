pub mod diagnostics;
pub mod doctor;
pub mod help;
pub mod network;
mod pages;
mod render;
pub mod settings;
pub mod site;
mod state;
pub mod tor;

pub use doctor::{run_fast_doctor, DoctorContext, DoctorLiveState, DoctorReport};
pub use pages::Page;
pub use render::render;
pub use state::{DiagnosticsPageState, MenuOpenTarget, MenuState};
