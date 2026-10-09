//! Language models: what libraries and frameworks do with data.

pub mod c;
pub mod cmem;
pub mod cnull;
pub mod common;
pub mod java;
pub mod php;
pub mod python;

use crate::interp::Model;
use crate::Language;

static PYTHON: python::Python = python::Python;
static JAVA: java::Java = java::Java;
static PHP: php::Php = php::Php;
static C: c::C = c::C;

/// The library model for code in `lang`.
pub fn for_language(lang: Language) -> &'static dyn Model {
    match lang {
        Language::Python => &PYTHON,
        Language::Java => &JAVA,
        Language::Php => &PHP,
        Language::C | Language::Cpp => &C,
    }
}
