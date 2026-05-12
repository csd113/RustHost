pub mod doctor;
mod pages;
mod render;
mod state;

pub use doctor::{run_fast_doctor, DoctorContext, DoctorLiveState, DoctorReport};
pub use pages::Page;
pub use render::render;
pub use state::{MenuOpenTarget, MenuState};
